// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title Multi-Call Aggregator with Exception Disorder
/// @notice Exception disorder hidden in a batch execution pattern:
///         sub-call failures are swallowed via try/catch or low-level calls,
///         but state changes proceed regardless. Multi-step: register targets,
///         queue calls, execute batch.
contract CallAggregator {
    struct CallTarget {
        address payable target;
        bool trusted;
        uint256 gasLimit;
    }

    struct QueuedCall {
        uint256 targetId;
        uint256 value;
        bytes data;
        bool executed;
        bool succeeded;
    }

    mapping(uint256 => CallTarget) public targets;
    uint256 public targetCount;
    QueuedCall[] public callQueue;
    mapping(address => uint256) public credits;
    uint256 public totalProcessed;
    uint256 public totalFailed;
    address public operator;
    bool public processingActive;

    event TargetRegistered(uint256 id, address target);
    event CallQueued(uint256 callId);
    event CallExecuted(uint256 callId, bool success);
    event BatchCompleted(uint256 processed, uint256 failed);

    constructor() {
        operator = msg.sender;
    }

    // Step 1: Register call targets
    function registerTarget(address payable target, uint256 gasLimit) external returns (uint256) {
        require(msg.sender == operator, "Not operator");
        uint256 id = targetCount++;
        targets[id] = CallTarget({
            target: target,
            trusted: false,
            gasLimit: gasLimit
        });
        emit TargetRegistered(id, target);
        return id;
    }

    function trustTarget(uint256 targetId) external {
        require(msg.sender == operator, "Not operator");
        require(targetId < targetCount, "Invalid target");
        targets[targetId].trusted = true;
    }

    function addCredits() external payable {
        credits[msg.sender] += msg.value;
    }

    // Step 2: Queue calls for batch execution
    function queueCall(uint256 targetId, uint256 value, bytes calldata data) external returns (uint256) {
        require(targetId < targetCount, "Invalid target");
        require(credits[msg.sender] >= value, "Insufficient credits");

        credits[msg.sender] -= value;

        uint256 callId = callQueue.length;
        callQueue.push(QueuedCall({
            targetId: targetId,
            value: value,
            data: data,
            executed: false,
            succeeded: false
        }));
        emit CallQueued(callId);
        return callId;
    }

    // Step 3: Execute batch — BUG: exceptions are swallowed
    function executeBatch(uint256 startIdx, uint256 count) external {
        require(msg.sender == operator, "Not operator");
        require(!processingActive, "Already processing");
        processingActive = true;

        uint256 processed = 0;
        uint256 failed = 0;

        for (uint256 i = startIdx; i < startIdx + count && i < callQueue.length; i++) {
            QueuedCall storage qc = callQueue[i];
            if (qc.executed) continue;

            CallTarget storage ct = targets[qc.targetId];
            qc.executed = true;

            // BUG: low-level call — failure is logged but state changes
            // (executed = true, totalProcessed++) continue regardless
            (bool ok, ) = ct.target.call{value: qc.value, gas: ct.gasLimit}(qc.data);
            qc.succeeded = ok;

            if (ok) {
                processed++;
            } else {
                failed++;
                // BUG: credits are NOT refunded on failure — user loses funds
            }

            // State update happens regardless of call success
            totalProcessed += 1;
            emit CallExecuted(i, ok);
        }

        totalFailed += failed;
        processingActive = false;
        emit BatchCompleted(processed, failed);
    }

    // BUG: try/catch that swallows exceptions — balance already deducted
    function executeWithFallback(uint256 callId) external {
        require(msg.sender == operator, "Not operator");
        QueuedCall storage qc = callQueue[callId];
        require(!qc.executed, "Already executed");

        CallTarget storage ct = targets[qc.targetId];
        qc.executed = true;

        try this._doCall(ct.target, qc.value, qc.data) {
            qc.succeeded = true;
            totalProcessed += 1;
        } catch {
            // BUG: exception swallowed — call failed but qc.executed = true
            // Credits are lost, no refund mechanism
            qc.succeeded = false;
            totalFailed += 1;
            totalProcessed += 1;
        }
    }

    function _doCall(address payable target, uint256 value, bytes calldata data) external {
        require(msg.sender == address(this), "Internal only");
        (bool ok, ) = target.call{value: value}(data);
        require(ok, "Call failed");
    }

    // BUG: delegatecall without checking success
    function upgradeAndExecute(address impl, bytes calldata data) external {
        require(msg.sender == operator, "Not operator");
        (bool success, ) = impl.delegatecall(data);
        // success captured but NOT checked — silent failure
        totalProcessed += 1;
    }

    function queueLength() external view returns (uint256) {
        return callQueue.length;
    }

    function getCredits(address user) external view returns (uint256) {
        return credits[user];
    }
}
