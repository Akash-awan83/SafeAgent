from safeagent.execution import normalize_safe_command
from safeagent.ml_pipeline import classification_metrics, stratified_split
from safeagent.models import RiskCategory


def test_windows_safe_aliases_are_normalized_but_dangerous_commands_are_not():
    assert normalize_safe_command("pwd", RiskCategory.SAFE, system="Windows") == "cd"
    assert normalize_safe_command("ls -la", RiskCategory.SAFE, system="Windows") == "dir -la"
    assert normalize_safe_command("rm -rf build", RiskCategory.DANGEROUS, system="Windows") == "rm -rf build"
    assert normalize_safe_command("pwd", RiskCategory.SAFE, system="Linux") == "pwd"


def test_pipeline_metrics_and_split_are_stratified():
    commands = ["safe-1", "safe-2", "safe-3", "safe-4", "unsafe-1", "unsafe-2", "unsafe-3", "unsafe-4"]
    labels = [0, 0, 0, 0, 1, 1, 1, 1]
    train_commands, train_labels, validation_commands, validation_labels = stratified_split(commands, labels)
    assert len(train_commands) + len(validation_commands) == len(commands)
    assert {0, 1}.issubset(train_labels)
    assert {0, 1}.issubset(validation_labels)
    metrics = classification_metrics([0, 0, 1, 1], [0.1, 0.7, 0.9, 0.2])
    assert metrics.false_positives == 1
    assert metrics.false_negatives == 1
    assert metrics.accuracy == 0.5
