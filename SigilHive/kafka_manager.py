import json
import os
import sys
import time
import asyncio
from typing import Any, Callable, Dict, List, Optional
from collections import defaultdict
from confluent_kafka import Producer, Consumer, KafkaException


def log(message: str):
    print(message, file=sys.stderr, flush=True)
    print(message, file=sys.stdout, flush=True)


class HoneypotKafkaManager:
    def __init__(self, bootstrap_servers=None, max_retries=None, retry_delay=None):
        log("🚀 [Kafka Manager] Initializing HoneypotKafkaManager...")

        if bootstrap_servers is None:
            bootstrap_servers = os.getenv(
                "KAFKA_BOOTSTRAP_SERVERS",
                os.getenv("KAFKA_BROKER", "kafka:9092"),
            )

        # Read retry config from env vars so Kubernetes deployments can tune
        # without rebuilding the image. Defaults are generous (20 retries, 3s delay)
        # to survive GKE Autopilot cold-start where Kafka takes 60-90s to be ready.
        if max_retries is None:
            max_retries = int(os.getenv("KAFKA_MAX_RETRIES", "20"))
        if retry_delay is None:
            retry_delay = int(os.getenv("KAFKA_RETRY_DELAY", "3"))

        log(f"🔧 [Kafka Manager] Bootstrap servers: {bootstrap_servers}")

        self.producer_config = {
            "bootstrap.servers": bootstrap_servers,
            "linger.ms": 10,
            "compression.type": "snappy",
        }
        self.consumer_config = {
            "bootstrap.servers": bootstrap_servers,
            "group.id": "honeypot-tracker",
            "auto.offset.reset": "earliest",
        }

        self.topics: Optional[List[str]] = None
        self.message_buffer: Dict[str, list] = defaultdict(list)
        self.enabled = False
        self.producer = None
        self.consumer = None
        self.message_count = 0

        # FIX: per-topic callback registry.
        # Handlers are registered by honeypot controllers so that incoming
        # cross-protocol messages actually influence honeypot behaviour.
        self._handlers: Dict[str, List[Callable[[dict], None]]] = defaultdict(list)

        log(f"🔄 [Kafka Manager] Attempting to connect (max {max_retries} retries)...")

        for attempt in range(max_retries):
            try:
                log(f"🔌 Connection attempt {attempt + 1}/{max_retries}...")
                self.producer = Producer(self.producer_config)
                self.consumer = Consumer(self.consumer_config)
                self.producer.list_topics(timeout=5)
                self.enabled = True
                log(f"✅ [Kafka Manager] Connected to Kafka at {bootstrap_servers}")
                break
            except KafkaException as e:
                if attempt < max_retries - 1:
                    log(
                        f"⏳ Attempt {attempt + 1}/{max_retries} failed, retrying in {retry_delay}s... ({e})"
                    )
                    time.sleep(retry_delay)
                else:
                    log(f"⚠️ [Kafka Manager] Failed after {max_retries} attempts: {e}")
                    log("⚠️ [Kafka Manager] Running WITHOUT Kafka support")
            except Exception as e:
                log(f"❌ [Kafka Manager] Unexpected error: {e}")
                break

    # ──────────────────────────────────────────────────────────────────
    # FIX: handler registration API
    # ──────────────────────────────────────────────────────────────────
    def register_handler(self, topic: str, callback: Callable[[dict], None]) -> None:
        """
        Register *callback* to be invoked whenever a message arrives on
        *topic*.  Multiple callbacks per topic are supported.

        Call this from a honeypot controller's __init__ *before* starting
        the consume() coroutine, e.g.:

            self.kafka_manager.register_handler(
                "HTTPtoDB", self._on_http_event
            )

        The callback receives the deserialized payload dict.  It must be
        synchronous (wrap with asyncio.create_task if async work is needed).
        """
        self._handlers[topic].append(callback)
        log(f"📋 [Kafka] Handler registered for topic '{topic}'")

    def _dispatch(self, topic: str, payload: dict) -> None:
        """Invoke all registered callbacks for *topic*."""
        for handler in self._handlers.get(topic, []):
            try:
                handler(payload)
            except Exception as e:
                log(f"❌ [Kafka] Handler error on topic '{topic}': {e}")

    # ──────────────────────────────────────────────────────────────────
    # Unchanged producer helpers
    # ──────────────────────────────────────────────────────────────────
    def delivery_report(self, err: str, msg: Any):
        if err:
            log(f"❌ [Kafka Producer] Message delivery failed: {err}")
        else:
            self.message_count += 1
            if self.message_count % 50 == 0:
                log(f"✅ [Kafka Producer] {self.message_count} messages delivered")

    def send(self, topic: str, value: dict, **kwargs):
        if kwargs:
            log(f"ℹ️ [Kafka Send] Ignoring extra parameters: {list(kwargs.keys())}")
        if not self.enabled or self.producer is None:
            return
        try:
            if isinstance(value, dict):
                value_bytes = json.dumps(value).encode("utf-8")
            elif isinstance(value, str):
                value_bytes = value.encode("utf-8")
            else:
                value_bytes = str(value).encode("utf-8")
            self.producer.produce(
                topic=topic, value=value_bytes, callback=self.delivery_report
            )
            self.producer.poll(0)
            if self.message_count % 100 == 0:
                self.producer.flush()
        except BufferError:
            self.producer.flush()
            self.producer.produce(
                topic=topic, value=value_bytes, callback=self.delivery_report
            )
        except Exception as e:
            log(f"❌ [Kafka Send] Failed to send to '{topic}': {e}")

    def send_dashboard(
        self, topic: str, value: Any, service: str = "unknown", event_type: str = "log"
    ):
        if not self.enabled or self.producer is None:
            return
        if isinstance(value, dict):
            payload = value.copy()
        elif isinstance(value, str):
            payload = {"message": value}
        else:
            payload = {"message": str(value)}
        payload.update(
            {"service": service, "event_type": event_type, "timestamp": time.time()}
        )
        value_bytes = json.dumps(payload).encode("utf-8")
        try:
            self.producer.produce(
                topic=topic, value=value_bytes, callback=self.delivery_report
            )
            self.producer.poll(0)
            if self.message_count % 100 == 0:
                self.producer.flush()
        except BufferError:
            self.producer.flush()
            self.producer.produce(
                topic=topic, value=value_bytes, callback=self.delivery_report
            )
        except Exception as e:
            log(f"❌ [Kafka Dashboard] Failed to send to '{topic}': {e}")

    def subscribe(self, topics: list):
        if not self.enabled or self.consumer is None:
            log("⚠️ [Kafka Subscribe] Kafka not available")
            return
        self.topics = topics
        self.consumer.subscribe(topics)
        log(f"📥 [Kafka Subscribe] Subscribed to: {topics}")

    # ──────────────────────────────────────────────────────────────────
    # FIX: consume() dispatches to registered handlers instead of only
    #      buffering (the buffer was never read by anything).
    # ──────────────────────────────────────────────────────────────────
    async def consume(self):
        if not self.enabled or self.consumer is None:
            log("⚠️ [Kafka Consumer] Not available — consumer NOT started")
            return

        log(f"🔄 [Kafka Consumer] Active — topics: {self.topics}")

        try:
            iteration = 0
            while True:
                iteration += 1
                if iteration % 300 == 0:
                    log(f"💓 [Kafka Consumer] Heartbeat — {iteration} polls")

                # BUG-5 FIX: run blocking poll() in a thread
                msg = await asyncio.to_thread(self.consumer.poll, 1.0)

                if msg is None:
                    pass
                elif msg.error():
                    log(f"❌ [Kafka Consumer] Error: {msg.error()}")
                else:
                    topic = msg.topic()
                    try:
                        payload = json.loads(msg.value().decode("utf-8"))
                    except Exception:
                        payload = {"raw": msg.value().decode("utf-8", errors="ignore")}

                    self._dispatch(topic, payload)

                    self.message_buffer[topic].append(payload)
                    if len(self.message_buffer[topic]) > 500:
                        self.message_buffer[topic] = self.message_buffer[topic][-500:]

                # No sleep needed — poll() already blocks for up to 1s in the thread.
                # A small yield keeps the loop cooperative if poll returns immediately.
                await asyncio.sleep(0)

        except Exception as e:
            log(f"❌ [Kafka Consumer] Critical error: {e}")
            import traceback

            log(traceback.format_exc())
        finally:
            if self.consumer:
                log("🛑 [Kafka Consumer] Closing consumer...")
                self.consumer.close()
                log("✅ [Kafka Consumer] Closed")

    def close(self):
        log("🛑 [Kafka Manager] Shutting down...")
        if self.producer:
            self.producer.flush(timeout=5)
        if self.consumer:
            self.consumer.close()
        log("✅ [Kafka Manager] Shutdown complete")