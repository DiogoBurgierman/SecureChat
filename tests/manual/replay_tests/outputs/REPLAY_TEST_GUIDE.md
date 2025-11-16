
# Replay Attack Test Guide (Windows)

## Objective
Verify that replay attacks are prevented using sequence numbers (REPLAY error).

## Test Procedure

### Method 1: Modify Client Code (Recommended)

1. **Start the server:**
   ```powershell
   python app/server.py
   ```

2. **Modify `app/client.py` temporarily:**
   
   Find the message sending function and add code to resend the same message:
   
   ```python
   def send_chat_message(self, message: str):
       # ... existing code to send message ...
       
       # REPLAY TEST: Resend the same message
       print("[REPLAY TEST] Resending same message...")
       # Resend the exact same JSON message
       self.sock.sendall(message_json.encode('utf-8'))
   ```

3. **In another terminal, start the client:**
   ```powershell
   python app/client.py
   ```

4. **Complete authentication:**
   - Register or login with valid credentials
   - Wait for session key establishment

5. **Send a test message:**
   - Type: `Hello, this is message number 1`
   - Press Enter
   - The client will automatically resend it (replay)

6. **Observe the error:**
   - Server should output: `[ERROR] REPLAY: Sequence number X already used`
   - Server should output: `[ERROR] Message rejected - potential replay attack`
   - The replayed message should be rejected

7. **Take screenshot** of the error

8. **Revert the replay code** in `app/client.py`

## Expected Output

```
[ERROR] REPLAY: Sequence number 2 already used
[ERROR] Message rejected - potential replay attack
[ERROR] Expected sequence number: 4, got: 2
```

## Test Cases

### Test Case 1: Exact Replay
- Send message with seqno N
- Resend exact same message (same seqno, same signature)
- **Expected:** REPLAY error

### Test Case 2: Out-of-Order Sequence
- Send messages: 1, 2, 3
- Try to send message with seqno 2 again
- **Expected:** REPLAY error

## Evidence to Capture

1. Screenshot of first message (seqno: N)
2. Screenshot of replayed message (same seqno: N)
3. Screenshot of REPLAY error
4. Screenshot of server logs showing sequence number tracking

## Verification

After the test, verify:
- [OK] Replayed messages are rejected
- [OK] Error message clearly indicates REPLAY
- [OK] Server continues to accept new messages with correct sequence numbers
- [OK] Sequence number tracking is maintained correctly
