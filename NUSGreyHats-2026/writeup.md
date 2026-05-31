# GreyHats CTF 2026 — Writeup Summary

---

## 1. Spidr (Reverse Engineering)

**What:** A 64-bit binary with a heavily obfuscated state machine spread across 100 chained C++ functions, each with 99 states. Input is a `uint64_t` transformed through 9,900 operations (XOR, ADD, MUL mod 2⁶⁴), then compared to a target value.

**Attack:** Traced the full execution path across all 100 functions, then reversed every operation backwards from the target — modular inverse for multiplications, subtraction for additions, XOR again for XORs.

**Takeaway:** Obfuscation through volume is not security. Every operation was individually invertible. The entire thing collapsed in one Python script once the structure was understood.

> **ELI5:** Imagine someone scrambles a Rubik's cube using 9,900 moves and asks you to figure out the starting position. Sounds hard — but if you filmed every move, you can just rewind the tape. That's all we did.

---

## 2. Jailbreak (Python Sandbox Escape)

**What:** Python `eval()` sandbox with no builtins, a character whitelist (no commas), and a keyword blacklist (`open`, `os`, `sys`, etc.). Max 167 characters.

**Attack:** Even with builtins wiped, Python's object model is fully accessible through any object. From a plain empty string `""`, you can navigate:

```
"".__class__              → str
  .__bases__[0]           → object
  .__subclasses__()[134]  → FileLoader (Python's internal file reader)
```

`FileLoader.get_data(path)` only needs one argument (no comma needed). But its constructor needs two, so we used `__new__` to create an uninitialized instance without calling `__init__`. The walrus operator `:=` stored the class to avoid repeating the long chain and stay under 167 chars.

```python
(c:="".__class__.__bases__[0].__subclasses__()[134]) and c.__new__(c).get_data("flag.txt")
```

**Why each defence failed:**
| Defence | Why it didn't work |
|---|---|
| `__builtins__ = {}` | Removed named builtins, but the object model itself is untouched |
| No commas | We found a method that only needs one argument |
| Keyword blacklist | We never used any blacklisted names |
| 167 char limit | Walrus operator kept it to 90 chars |

**Takeaway:** Blacklisting names doesn't work when the language's own object model has infinite detours. As long as `eval` can touch *any* Python object — even just `""` — you can navigate to virtually any capability in the runtime. `__subclasses__()` exposes every class loaded in the process. Real fix: never `eval` user input.

> **ELI5:** The jail said "you can't use the front door" and blocked every entrance it could think of. But Python is like a building where every room has a secret passage to every other room — even an empty string `""` knows how to reach the file system if you know where to look. We crawled through the internal plumbing to find a file-reading tool that was already sitting in memory, waiting to be used.

---

## 3. Broken CBC / PCBC Oracle (Cryptography)

**What:** Custom AES mode where `state = plaintext XOR ciphertext` — this is actually PCBC mode. An oracle decrypts submitted ciphertexts and shows any block that's printable ASCII. Can't resubmit the original ciphertext.

**Attack:** Two queries:
- **Query 1:** Flip a bit in the last ciphertext block → blocks 0–3 decrypt correctly and are revealed (64/80 bytes of flag)
- **Query 2:** **PCBC swap property** — swapping two adjacent ciphertext blocks (c2 ↔ c3) garbles those two but leaves everything *after* them intact. Block 4 decrypts to the real flag ending.

**Takeaway:** PCBC mode has a known published vulnerability — swapping adjacent blocks causes errors that cancel out for all subsequent blocks. Blocking the exact original ciphertext is useless if the mode itself is malleable. Authenticated encryption (AES-GCM) prevents this entirely.

> **ELI5:** The cipher was like a game of telephone where each person's message depends on what the previous person said AND what they passed forward. We discovered that if you swap two people in the middle of the line, their messages get scrambled — but everyone *after* them magically hears the correct message again. That loophole let us read the end of the flag.

---

## 4. AES Without SubBytes (Cryptography)

**What:** AES with the SubBytes step removed. SubBytes is the only nonlinear step — without it the entire cipher is a linear transformation over GF(2⁸).

**Attack:** Without SubBytes, encryption is just `output = M × input + c`. Recovered the full matrix by encrypting the all-zeros block (gets the constant `c`) and each of the 128 single-bit inputs (each reveals one column of M). Then inverted M to decrypt the flag directly. The challenge handed us all 129 encryptions needed in `output.txt`.

**Takeaway:** SubBytes is the *entire* source of AES's security. ShiftRows and MixColumns only exist to *spread* the nonlinearity around. Remove SubBytes and you have a linear cipher breakable with 129 chosen plaintexts — just a matrix equation.

> **ELI5:** Normal AES is like a blender — you can't un-blend a smoothie. SubBytes is the blender blade. The other steps (ShiftRows, MixColumns) just push the ingredients around. Remove the blade and now it's just a bowl with a spoon — you can easily separate everything back out with basic maths.

---

## 5. Babyheap (Binary Exploitation)

**What:** C++ heap challenge. Two vectors (`Monkey` and `Greycat`) pre-allocated contiguously on the heap. `Greycat` has a function pointer `speak` at offset 40 within the struct. `cin >> name` reads into `name[32]` with no bounds check. Hidden option `6767` leaks the `malloc` address.

**Attack:**
- Leak `malloc` via option `6767` → compute `system()` address via libc offset
- Create 8 greycats with dummy names
- Create greycat[8] with overflow payload: the name field overflows 12 extra bytes directly into `speak` within the same object, replacing it with `system()`
- Call `greycats[8].talk()` → `speak(name)` → `system("cat<flag.txt")`

**Key debug moments:**
- Initial approach overflowed monkey[9] across the heap chunk boundary into the greycat buffer — crashed due to heap metadata corruption
- `"cat flag.txt"` has a space which terminates `cin >>` early, flooding the menu with garbage — fixed to `cat<flag.txt` (shell redirect, no space)
- Libc offset identification: the leaked malloc address ended in `0x0a0`, which didn't match any standard Ubuntu 22.04 glibc 2.35 build — exact fingerprinting was the final hurdle

**Takeaway:** `cin >>` reads through null bytes but **stops at whitespace** — a subtle difference that broke the exploit for a long time. Overflowing within the same object avoids heap metadata corruption from crossing chunk boundaries. Libc fingerprinting (identifying the exact build from leaked address bits) is a real and sometimes painful skill in heap exploitation.

> **ELI5:** The program stored a phone number (function pointer) right next to a text field with no guardrails. We typed so much text it spilled over and replaced the phone number with our own. When the program dialled that number it called our chosen function (`system`) instead. The tricky part: we couldn't use spaces in the text — like how a form stops reading when you hit Enter — so we used a shell redirect trick (`cat<flag.txt`) to avoid them.
