"""
Q-Learning agent for adaptive honeypot control.

Implements tabular Q-learning with epsilon-greedy exploration.
The agent learns optimal deception strategies through interaction.
"""

import os
import pickle
import random
import threading
import time
from typing import Tuple, Optional, Dict
from .config import RL_CONFIG
from .action_dispatcher import ACTIONS, get_candidate_actions


class QLearningAgent:
    """
    Tabular Q-Learning agent with epsilon-greedy exploration.

    The Q-table maps (state, action) pairs to expected cumulative rewards.
    """

    def __init__(self, config: Dict = None):
        """
        Initialize Q-learning agent.

        Args:
            config: Configuration dictionary (uses RL_CONFIG if None)
        """
        self.config = config or RL_CONFIG

        # Hyperparameters
        self.learning_rate = self.config["learning_rate"]
        self.discount_factor = self.config["discount_factor"]
        self.epsilon = self.config["epsilon_start"]
        self.epsilon_min = self.config["epsilon_min"]
        self.epsilon_decay = self.config["epsilon_decay"]
        self.default_q_value = self.config["default_q_value"]

        # Q-table: {(protocol, state_tuple, action_str): q_value}
        self.q_table: Dict[Tuple[Tuple, str], float] = {}

        # Statistics
        self.update_count = 0
        self.action_counts = {action: 0 for action in ACTIONS}

        # Thread safety
        self.lock = threading.Lock()

        # Persistence
        self.q_table_path = self.config["q_table_path"]
        self.save_interval = self.config["save_interval"]

        # Load existing Q-table if available
        self.load_q_table()

        print(
            f"[QLearningAgent] Initialized with ε={self.epsilon:.3f}, α={self.learning_rate}, γ={self.discount_factor}"
        )

    def select_action(self, state: Tuple, protocol: Optional[str] = None) -> str:
        """
        Select action using epsilon-greedy policy.

        Args:
            state: State tuple (5 integers)

        Returns:
            Selected action string
        """
        candidates = get_candidate_actions(protocol=protocol, state=state, exploration=False)

        # Epsilon-greedy: explore with probability epsilon
        if random.random() < self.epsilon:
            action = random.choice(
                get_candidate_actions(protocol=protocol, state=state, exploration=True)
            )
        else:
            action = self.get_best_action(state, protocol=protocol, candidates=candidates)

        # Track action selection
        with self.lock:
            self.action_counts[action] += 1

        return action

    def get_best_action(
        self,
        state: Tuple,
        protocol: Optional[str] = None,
        candidates: Optional[list[str]] = None,
    ) -> str:
        """
        Get action with highest Q-value for given state.

        Args:
            state: State tuple

        Returns:
            Best action string
        """
        q_values = {}
        candidates = candidates or get_candidate_actions(protocol=protocol, state=state, exploration=False)

        for action in candidates:
            q_values[action] = self.get_q_value(state, action, protocol=protocol)

        # Return action with max Q-value (random tiebreaker)
        max_q = max(q_values.values())
        best_actions = [a for a, q in q_values.items() if q == max_q]

        return random.choice(best_actions)

    def _key(self, state: Tuple, action: str, protocol: Optional[str]) -> Tuple:
        return (protocol or "global", state, action)

    def get_q_value(self, state: Tuple, action: str, protocol: Optional[str] = None) -> float:
        """
        Get Q-value for state-action pair.

        Args:
            state: State tuple
            action: Action string

        Returns:
            Q-value (default 0.0 if unseen)
        """
        key = self._key(state, action, protocol)
        if key in self.q_table:
            return self.q_table[key]

        legacy_key = (state, action)
        return self.q_table.get(legacy_key, self.default_q_value)

    def update(
        self,
        state: Tuple,
        action: str,
        reward: float,
        next_state: Tuple,
        protocol: Optional[str] = None,
    ):
        """
        Update Q-value using Q-learning rule.

        Q(s,a) ← Q(s,a) + α[r + γ max Q(s',a') - Q(s,a)]

        Args:
            state: Current state
            action: Action taken
            reward: Reward received
            next_state: Resulting state
        """
        with self.lock:
            # Get current Q-value
            current_q = self.get_q_value(state, action, protocol=protocol)

            # Get max Q-value for next state
            candidates = get_candidate_actions(
                protocol=protocol, state=next_state, exploration=False
            )
            max_next_q = max(
                self.get_q_value(next_state, a, protocol=protocol)
                for a in candidates
            )

            # Compute TD target
            target = reward + self.discount_factor * max_next_q

            # Update Q-value
            new_q = current_q + self.learning_rate * (target - current_q)

            # Store in Q-table
            key = self._key(state, action, protocol)
            self.q_table[key] = new_q

            # Decay epsilon
            self.decay_epsilon()

            # Update statistics
            self.update_count += 1

            # Periodic save
            if self.update_count % self.save_interval == 0:
                self.save_q_table()

        # Log significant updates (optional, can be disabled)
        if abs(target - current_q) > 1.0:  # Significant TD error
            print(
                f"[QLearningAgent] Large update: state={state}, action={action}, "
                f"reward={reward:.2f}, ΔQ={target - current_q:.2f}"
            )

    def decay_epsilon(self):
        """Decay exploration rate"""
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)

    def save_q_table(self, path: Optional[str] = None):
        """
        Save Q-table to disk.

        Args:
            path: File path (uses default if None)
        """
        path = path or self.q_table_path

        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(path), exist_ok=True)

            data = self._build_merged_snapshot(path)

            with open(path, "wb") as f:
                pickle.dump(data, f)

            print(
                f"[QLearningAgent] Q-table saved: {len(self.q_table)} entries, "
                f"ε={self.epsilon:.4f}, updates={self.update_count}"
            )

        except Exception as e:
            print(f"[QLearningAgent] Error saving Q-table: {e}")

    def load_q_table(self, path: Optional[str] = None):
        """
        Load Q-table from disk.

        Args:
            path: File path (uses default if None)
        """
        path = path or self.q_table_path

        if not os.path.exists(path):
            print(f"[QLearningAgent] No existing Q-table found at {path}")
            return

        try:
            with open(path, "rb") as f:
                data = pickle.load(f)

            self.q_table = data.get("q_table", {})
            self.epsilon = data.get("epsilon", self.epsilon)
            self.update_count = data.get("update_count", 0)
            self.action_counts = data.get("action_counts", self.action_counts)

            print(
                f"[QLearningAgent] Q-table loaded: {len(self.q_table)} entries, "
                f"ε={self.epsilon:.4f}, updates={self.update_count}"
            )

        except Exception as e:
            print(f"[QLearningAgent] Error loading Q-table: {e}")

    def get_statistics(self) -> Dict:
        """
        Get agent statistics.

        Returns:
            Dictionary of statistics
        """
        return {
            "q_table_size": len(self.q_table),
            "epsilon": self.epsilon,
            "update_count": self.update_count,
            "action_counts": self.action_counts.copy(),
            "action_distribution": {
                action: count / max(sum(self.action_counts.values()), 1)
                for action, count in self.action_counts.items()
            },
        }

    def reset_epsilon(self, epsilon: Optional[float] = None):
        """
        Reset epsilon to start value or specified value.

        Args:
            epsilon: New epsilon value (uses epsilon_start if None)
        """
        self.epsilon = epsilon or self.config["epsilon_start"]
        print(f"[QLearningAgent] Epsilon reset to {self.epsilon:.3f}")

    def print_statistics(self):
        """Print agent statistics"""
        stats = self.get_statistics()

        print("\n" + "=" * 70)
        print("Q-LEARNING AGENT STATISTICS")
        print("=" * 70)
        print(f"Q-table size:      {stats['q_table_size']} state-action pairs")
        print(f"Total updates:     {stats['update_count']}")
        print(f"Current epsilon:   {stats['epsilon']:.4f}")
        print(f"\nAction Distribution:")

        for action, prob in stats["action_distribution"].items():
            count = stats["action_counts"][action]
            print(f"  {action:25s}: {prob * 100:5.1f}% ({count} times)")

        print("=" * 70 + "\n")

    def _build_merged_snapshot(self, path: str) -> Dict:
        """
        Merge the current in-memory table with any persisted shared table.
        This reduces data loss when multiple honeypot containers save to the
        same shared RL storage volume.
        """
        merged_q = dict(self.q_table)
        merged_counts = dict(self.action_counts)
        merged_updates = self.update_count
        merged_epsilon = self.epsilon

        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    existing = pickle.load(f)
                existing_q = existing.get("q_table", {})
                for key, value in existing_q.items():
                    if key in merged_q:
                        merged_q[key] = (merged_q[key] + value) / 2.0
                    else:
                        merged_q[key] = value

                for action, count in existing.get("action_counts", {}).items():
                    merged_counts[action] = max(merged_counts.get(action, 0), count)

                merged_updates = max(merged_updates, int(existing.get("update_count", 0)))
                merged_epsilon = min(merged_epsilon, float(existing.get("epsilon", merged_epsilon)))
            except Exception:
                pass

        return {
            "q_table": merged_q,
            "epsilon": merged_epsilon,
            "update_count": merged_updates,
            "action_counts": merged_counts,
            "saved_at": time.time(),
        }


# ==============================================================================
# SHARED AGENT SINGLETON
# ==============================================================================

# Create a single shared agent instance used by all honeypots
shared_rl_agent = QLearningAgent(RL_CONFIG)


# ==============================================================================
# TESTING
# ==============================================================================

if __name__ == "__main__":
    # Test agent
    agent = QLearningAgent()

    # Test state
    test_state = (1, 2, 1, 0, 0)

    # Select actions
    print("Testing action selection:")
    for i in range(10):
        action = agent.select_action(test_state)
        print(f"  {i + 1}. {action}")

    # Test Q-value update
    print("\nTesting Q-value update:")
    next_state = (1, 2, 2, 0, 1)
    reward = 5.0

    print(f"Initial Q-value: {agent.get_q_value(test_state, 'DECEPTIVE_RESOURCE'):.3f}")
    agent.update(test_state, "DECEPTIVE_RESOURCE", reward, next_state)
    print(f"Updated Q-value: {agent.get_q_value(test_state, 'DECEPTIVE_RESOURCE'):.3f}")

    # Print statistics
    agent.print_statistics()

    # Test save/load
    print("Testing save/load:")
    agent.save_q_table("test_q_table.pkl")
    agent.load_q_table("test_q_table.pkl")
