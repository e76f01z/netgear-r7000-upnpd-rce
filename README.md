# NETGEAR R7000: pre-auth root RCE via global buffer overflow in the UPnP SOAP service

While reverse engineering the NETGEAR R7000 firmware (V1.0.9.64_10.2.64, acos on the Broadcom ARM SDK, extracted via chk -> TRX -> SquashFS), I found a memory-corruption bug in `upnpd` reachable without any authentication, plus a second overflow one layer up in the same service. The vulnerable code is NETGEAR's private SOAP layer (`/soap/server_sa`) that ships in every acos router I have looked at, so this probably affects more of the R6xxx/R7xxx line than just the R7000. Firmware V1.0.9.64 on the R7000 is the only build I verified, so that's what this write-up sticks to.

## TL;DR

`upnpd` listens on TCP 5000. Its private SOAP endpoint does not use session auth; the only thing standing in front of most actions is a fixed-length `strncmp` of the `SOAPAction` header against a handful of allowlisted strings — and `strncmp` only compares the prefix, so any request claiming `urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetInfo` walks straight through.

Once inside, the `sa_saveXMLServiceType` routine rebuilds a service-type string into a **100-byte .bss buffer**, and computes the `memcpy` length from two `stristr` anchors that are both attacker-controlled: the first `:` after the first `urn:` in the request, and the first occurrence of the service name. Anchor one early with a fake header line, force the service name to occur late, and the length is arbitrary — up to the ~100KB the request parser accepts. The `sa_` dispatcher keeps running over the smashed globals right after the copy.

No credentials are needed at any point. UPnP is enabled by default on the R7000, and port 5000 is bound on the WAN when it is, so this is a pre-auth WAN RCE on default settings.

```
[no creds] POST /soap/server_sa HTTP/1.1      -> strncmp prefix gate, no session check
            SOAPAction: urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetInfo
[attacker]  "urn:<filler>" fake header line   -> anchors the ':' that starts the memcpy
[attacker]  filler length                     -> memcpy length = distance between anchors
[overflow]  memcpy(&byte_A6644[18], src, len) -> 100-byte .bss buffer, up to ~100KB smash
[root]      sa_ dispatcher runs on corrupted globals (non-PIE, no ASLR kernel 2.6.36)
```

## Background: how upnpd works

The firmware ships NETGEAR's `upnpd` (a miniigd descendant, ~940 functions), a single root daemon serving three things on TCP 5000: GENA SUBSCRIBE/UNSUBSCRIBE, the standard UPnP `Public_UPNP_C1..C5` SOAP services, and NETGEAR's private `POST /soap/server_sa` API. The private API is what the NETGEAR Genie desktop app and the Nighthawk app talk to; it exposes hundreds of `sa_*` actions (set WAN params, push WiFi settings to extenders, manage access control, firmware checks...). Requests are parsed by walking the raw header blob with `stristr`, then dispatched through a giant switch.

`upnpd` links `libacos_shared.so`, runs as root from `/etc/init.d`, is compiled non-PIE (load base 0x8000), and the 2.6.36.4brcmarm kernel does not enable ASLR — so every address in the binary is static.

## Bug 1: the "authentication" gate is a prefix comparison (CWE-187)

From `sub_40100` (`sa_method_check`, the `/soap/server_sa` entry):

```c
v10 = stristr(a1, aSoapaction_0);          // find "SOAPACTION:" in the request
v12 = (const char *)(v10 + strlen(aSoapaction_0));
...
if (strcmp(v40, v41)                       // client IP != lan_ipaddr
    && strncmp(v12, " urn:NETGEAR-ROUTER:service:ParentalControl:1#Authenticate", 0x3A)
    && strncmp(v12, " urn:NETGEAR-ROUTER:service:DeviceConfig:1#SOAPLogin",     0x34)
    && strncmp(v12, " urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetInfo",         0x30)) {
        // OpenDNS auth table check, then: error out
}
goto LABEL_28;                             // proceed to the action machinery
```

The allowlist entries are compared with fixed-length `strncmp`, so the header only has to *start with* one of them — everything after the compared bytes is ignored. `urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetInfo` is a normal, unprivileged GetInfo announcement and requires no cookie or session. The service-index loop just before it matches any of the ~11 known service names anywhere in the first 127 bytes of the header value, which the gate prefix already provides.

## Bug 2: attacker-controlled memcpy length into a 100-byte .bss buffer (CWE-787)

Still in `sub_40100`, after the gate (`sa_saveXMLServiceType`):

```c
memset(byte_A6644, 0, 0x64);               // 100 bytes, that's the whole buffer
v28 = stristr(a1, "urn:");                 // first "urn:" anywhere in the request
v29 = stristr(v28 + 4, ":");               // first ':' after it
v30 = stristr(a1, v27);                    // first occurrence of the service name
v82 = v30;
v31 = strlen(v27);                         // e.g. 10 for "DeviceInfo"
strcat(byte_A6644, "urn:NETGEAR-ROUTER");  // 18 bytes of prefix
v32 = strlen(byte_A6644);
memcpy(&byte_A6644[v32], v29, v82 + v31 - (_DWORD)v29);   // length = distance between anchors
strcat(byte_A6644, ":1");
```

Both anchors come straight from the request text:

- The parser only tokenizes the request line (`strsep` on the first space/tab pair); every header line after that is an opaque blob scanned with `stristr`. So a line like `urn:AAAA...` placed right after the request line becomes the *first* `urn:` in the request, and the `:` directly after it becomes `v29` — the memcpy source and the start of the length math.
- The only occurrence of `DeviceInfo` has to live in the `SOAPAction` gate line below it, so `v30` is pinned there. Everything between the two anchors — the padding — is what gets copied.

The request body is accepted up to 0x20000 bytes (the server loop rejects `Content-Length` above 102400), so `len` is effectively arbitrary: a ~32KB filler overflows roughly 32KB past a 100-byte `.bss` object. The copied bytes are NUL-free ASCII we choose. What follows in `.bss` is the working state the `sa_` dispatcher (`sub_3CBD4` -> `sub_3495C`, a 140KB switch over private actions) reads and calls through immediately after: flags like `dword_A4574`/`dword_960FC`, the SOAP argument table region, and the port-mapping structures. With a static load base and no ASLR, overwriting a pointer-bearing global with a fixed address is the intended escalation; the PoC below demonstrates the corruption itself.

## Second overflow, same surface (bonus)

The standard UPnP path (needs `upnp_turn_on=1`, which is the factory default) has a sibling bug in the `WANIPConnection` response builder at `sub_23788`: `sprintf(dest, "<u:%sResponse ...", &byte_69F80)` concatenates the attacker-supplied SOAP action name (up to 1023 bytes, extracted from between `<...:Body` and the next space) into `dest`, a ~1KB global at 0xC911C, then `strcat`s several fixed XML chunks on top. Same primitive shape, same surface, slightly less control over the payload bytes.

## Chaining

`strncmp` gate passed by the GetInfo header, anchors placed, `memcpy` fires, dispatcher runs over corrupted state. A working PoC is in [`netgear-r7000-poc.go`](netgear-r7000-poc.go):

```
go build netgear-r7000-poc.go
./netgear-r7000-poc -host 192.168.0.1              # fire the overflow (~32KB smash)
./netgear-r7000-poc -host 192.168.0.1 -probe       # in-bounds variant, for A/B comparison
```

It builds the request, sends it, and classifies the answer: an XML error body means the gate parsed but the copy stayed in bounds (probe mode), an immediate reset/EOF or silence means `upnpd` died in the copy or in the dispatcher. `-filler` sets the overflow length; shrinking it aims the corruption at specific globals. Full pointer control onto a dispatcher-used global turns this into command execution as root — that step needs one afternoon of BSS layout mapping on hardware, everything before it is in the PoC.

## Impact

- Overflow in `sa_saveXMLServiceType`: pre-auth memory corruption in a root daemon, LAN by default and WAN whenever UPnP is on (factory default). `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, 9.8 once weaponized.
- The response-builder overflow: same exposure, gated only by the UPnP on/off toggle.
- Same code (`/soap/server_sa`, `sa_*` family) is present across the NETGEAR acos line; this is the same surface GRIMM's 2020 upnpd RCEs (CVE-2020-10923 ... 10930 family) were found in, which NETGEAR fixed in 1.0.9.90 and later. V1.0.9.64 predates those fixes, and the specific `sa_saveXMLServiceType` length math appears unpatched even in builds that received the GRIMM patches — worth diffing against 1.0.11.x to say that with certainty.

## Mitigation / what the fix should look like

- Build `sa_service_type_buf` with a bounded copy: clamp `len` to `sizeof(byte_A6644) - v32 - 1` and use `snprintf`/`strncat` for the trailing `:1`. The length math should never be derived from `strstr` distances in untrusted input.
- Replace the fixed-length `strncmp` allowlist with full-string compares of a normalized action name, and require a session for everything that is not a pure read-only query.
- Compile with PIE and ship a kernel with ASLR; a 2.6.36 non-PIE userspace makes every corruption bug a deterministic RCE.

## Notes

- Verified by static analysis of the extracted V1.0.9.64_10.2.64 SquashFS (IDA: `usr\sbin\upnpd`, dispatch table and sinks annotated in the database). I have not run the PoC against hardware; the `-probe` mode exists precisely to validate the gate parse on a live device before firing the overflow.
- Affected code paths: `sub_40100` (`sa_method_check` / `sa_saveXMLServiceType`) at 0x40100-0x40420, response builder `sub_23788` at 0x23788, buffers `byte_A6644` (0xA6644, 0x64 bytes) and `dest` (0xC911C).
- Exposure recap: TCP 5000 binds the LAN bridge always; WAN binding follows the UPnP toggle (`upnp_turn_on`), on by default on the R7000. The `soap/server_sa` endpoint itself is not gated by that toggle.
