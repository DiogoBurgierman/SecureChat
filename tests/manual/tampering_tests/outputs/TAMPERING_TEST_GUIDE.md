
# Message Tampering Test Guide (Windows)

## Objective
Verify that message integrity is protected and tampering is detected (SIG_FAIL).

## Test Procedure

### Method 1: Modify Client Code (Recommended)

1. **Start the server:**
   ```powershell
   python app/server.py
   ```

2. **Modify `app/client.py` temporarily:**
   
   Find the message sending code (around line 300-350) and add tampering:
   
   ```python
   # After encrypting the message
   ct = encrypt_aes128(plaintext.encode(), self.session_key)
   
   # TAMPER: Modify first byte of ciphertext
   ct_tampered = bytearray(ct)
   if len(ct_tampered) > 0:
       ct_tampered[0] = (ct_tampered[0] + 1) % 256
   ct = bytes(ct_tampered)
   ```

3. **In another terminal, start the client:**
   ```powershell
   python app/client.py
   ```

4. **Complete authentication:**
   - Register or login with valid credentials
   - Wait for session key establishment

5. **Send a test message:**
   - Type: `Hello, this is a test message for tampering`
   - Press Enter

6. **Observe the error:**
   - Server should output: `[ERROR] SIG_FAIL: Signature verification failed`
   - Server should output: `[ERROR] Message integrity check failed`
   - Connection may be terminated

7. **Take screenshot** of the error

8. **Revert the tampering code** in `app/client.py`

## Expected Output

```
[ERROR] SIG_FAIL: Signature verification failed
[ERROR] Message integrity check failed
[ERROR] Hash mismatch: expected abc123..., got def456...
Message rejected
```

## Evidence to Capture

1. Screenshot of original message being sent
2. Screenshot of SIG_FAIL error on server
3. Screenshot of server logs showing rejection

## Test Variations

- **Tamper with ciphertext (`ct` field)**: Should fail signature verification
- **Tamper with sequence number (`seqno`)**: Should fail hash verification
- **Tamper with timestamp (`ts`)**: Should fail hash verification
- **Tamper with signature (`sig`)**: Should fail signature verification

All variations should result in SIG_FAIL error.
