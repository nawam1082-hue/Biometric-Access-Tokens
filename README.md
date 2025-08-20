# 🔒 Biometric Access Tokens

A Clarity smart contract that enables secure access control using biometric authentication tied to blockchain tokens. This contract uses oracles to verify biometric hashes and mint time-limited access tokens.

## 🚀 Features

- 👆 **Biometric Registration**: Users can register their biometric hashes (fingerprints, face scans, etc.)
- 🔐 **Oracle-Based Verification**: Authorized oracles verify biometric data before minting tokens
- ⏰ **Time-Limited Tokens**: Access tokens have configurable expiration times
- 🛡️ **Access Control**: Protected resources require valid, non-expired tokens
- 📊 **Token Management**: Revoke tokens, batch operations, and user token tracking

## 📋 Contract Functions

### User Functions
- `register-biometric(biometric-hash)` - Register your biometric data 👤
- `update-biometric(new-biometric-hash)` - Update your biometric hash 🔄
- `deactivate-biometric()` - Deactivate your biometric registration ⏹️
- `revoke-token(token-id)` - Revoke your own access token 🚫
- `access-protected-resource(token-id)` - Access protected resources 🗝️

### Oracle Functions
- `verify-biometric-and-mint-token(user, biometric-hash, duration)` - Verify biometric and mint token 🎫

### Admin Functions
- `add-oracle(oracle)` - Add authorized oracle 🤝
- `remove-oracle(oracle)` - Remove oracle authorization ❌
- `batch-revoke-tokens(token-ids)` - Revoke multiple tokens at once 📦

### Read-Only Functions
- `get-biometric-data(user)` - Get user's biometric registration 📖
- `get-access-token(token-id)` - Get token details 🔍
- `is-oracle-authorized(oracle)` - Check oracle authorization status ✅
- `is-token-valid(token-id)` - Check if token is valid and not expired ⏱️
- `get-user-tokens(user)` - Get all tokens for a user 📝
- `get-contract-stats()` - Get contract statistics 📊

## 🔧 Usage Instructions

### 1. Deploy the Contract
```bash
clarinet deployments apply --devnet
```

### 2. Register Biometric Data
```clarity
(contract-call? .Biometric-Access-Tokens register-biometric 0x1234567890abcdef...)
```

### 3. Add Oracle (Admin Only)
```clarity
(contract-call? .Biometric-Access-Tokens add-oracle 'SP2ABC123...)
```

### 4. Verify Biometric & Mint Token (Oracle Only)
```clarity
(contract-call? .Biometric-Access-Tokens verify-biometric-and-mint-token 
  'SP2USER123... 
  0x1234567890abcdef... 
  u144) ;; 144 blocks = ~1 day
```

### 5. Access Protected Resource
```clarity
(contract-call? .Biometric-Access-Tokens access-protected-resource u1)
```

## ⚠️ Error Codes

- `u401` - Unauthorized access 🔐
- `u402` - Invalid biometric data 👆
- `u403` - Token expired ⏰
- `u404` - Oracle not found 🔍
- `u405` - Biometric already exists 🔄
- `u406` - Token not found 🎫

## 🏗️ Architecture

The contract uses three main data structures:

1. **Biometric Registry**: Stores user biometric hashes and registration status
2. **Access Tokens**: Time-limited tokens for resource access
3. **Authorized Oracles**: Trusted parties that can verify biometric data

## 🧪 Testing

Run the test suite:
```bash
clarinet test
```

## 🔐 Security Considerations

- Biometric hashes should be salted and hashed before registration
- Oracles must be trusted parties with proper security measures
- Token duration should be set appropriately for your use case
- Consider implementing rate limiting for sensitive operations

## 📄 License

MIT License - see LICENSE file for details.

---

**⚡ Built with Clarity on Stacks** 🟠
