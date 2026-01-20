LOG_TX = "🧾"
LOG_WARN = "⚠️"
LOG_EVENT = "📣"


def log_receipt(receipt) -> None:
    print(f"{LOG_TX} Extrinsic hash: {receipt.extrinsic_hash}")
    if getattr(receipt, "block_hash", None):
        print(f"{LOG_TX} Block hash: {receipt.block_hash}")
    if getattr(receipt, "finalized_hash", None):
        print(f"{LOG_TX} Finalized hash: {receipt.finalized_hash}")
    is_success = getattr(receipt, "is_success", None)
    if is_success is None:
        is_success = getattr(receipt, "success", True)
    print(f"{LOG_TX} Success: {is_success}")
    if not is_success:
        print(f"{LOG_WARN} Error: {receipt.error_message}")
    for event in receipt.triggered_events:
        module = event.value.get("module_id")
        name = event.value.get("event_id")
        print(f"{LOG_EVENT} Event: {module}.{name} {event.params}")
