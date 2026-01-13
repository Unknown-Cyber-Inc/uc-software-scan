#!/usr/bin/env node

/**
 * Creates test binary files with proper magic bytes for testing the scanner.
 * These are not real executables, just files with the correct magic signatures.
 */

const fs = require('fs');
const path = require('path');

// Magic byte signatures
const MAGIC = {
  ELF: Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]), // ELF 64-bit
  PE: Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]),  // PE/MZ
  MACHO: Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01]), // Mach-O 64-bit
  WASM: Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]), // WebAssembly
};

// Create a fake binary with magic bytes + some padding
function createFakeBinary(magic, size = 1024) {
  const buffer = Buffer.alloc(size);
  magic.copy(buffer);
  // Fill rest with random-ish data
  for (let i = magic.length; i < size; i++) {
    buffer[i] = (i * 17) % 256;
  }
  return buffer;
}

// Create a simple shell script
function createShellScript(content) {
  return `#!/bin/bash\n# Test script\n${content}\necho "Hello from test script"\n`;
}

// Create a simple batch script
function createBatchScript(content) {
  return `@echo off\nREM Test script\n${content}\necho Hello from test script\n`;
}

const testFiles = [
  // NPM ecosystem
  {
    path: 'test-ecosystems/npm-project/node_modules/@test/binary-pkg/binary.exe',
    content: createFakeBinary(MAGIC.PE)
  },
  {
    path: 'test-ecosystems/npm-project/node_modules/@test/binary-pkg/native.node',
    content: createFakeBinary(MAGIC.ELF)
  },
  {
    path: 'test-ecosystems/npm-project/node_modules/@test/binary-pkg/install.sh',
    content: createShellScript('npm install')
  },
  
  // Python/pip ecosystem
  {
    path: 'test-ecosystems/pip-project/site-packages/requests/_internal_utils.cpython-311-x86_64-linux-gnu.so',
    content: createFakeBinary(MAGIC.ELF)
  },
  {
    path: 'test-ecosystems/pip-project/site-packages/requests/setup.py',
    content: '#!/usr/bin/env python\n# Setup script\nprint("Installing...")\n'
  },
  
  // Maven ecosystem
  {
    path: 'test-ecosystems/maven-project/lib/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar',
    content: createFakeBinary(Buffer.from([0x50, 0x4b, 0x03, 0x04])) // ZIP magic (JAR is a ZIP)
  },
  
  // Cargo/Rust ecosystem
  {
    path: 'test-ecosystems/cargo-project/target/release/test-rust-app.exe',
    content: createFakeBinary(MAGIC.PE)
  },
  {
    path: 'test-ecosystems/cargo-project/target/release/libtest.dll',
    content: createFakeBinary(MAGIC.PE)
  },
  {
    path: 'test-ecosystems/cargo-project/target/release/test-rust-app',
    content: createFakeBinary(MAGIC.ELF)
  },
  
  // Go ecosystem
  {
    path: 'test-ecosystems/go-project/vendor/github.com/user/repo/helper.so',
    content: createFakeBinary(MAGIC.ELF)
  },
  {
    path: 'test-ecosystems/go-project/vendor/github.com/user/repo/build.sh',
    content: createShellScript('go build .')
  },
  
  // Multi-ecosystem project (simulates a container with multiple package managers)
  {
    path: 'test-ecosystems/container-extracted/node_modules/lodash/package.json',
    content: JSON.stringify({ name: 'lodash', version: '4.17.21' }, null, 2)
  },
  {
    path: 'test-ecosystems/container-extracted/node_modules/lodash/lodash.min.js',
    content: '// lodash minified\nmodule.exports = {};\n'
  },
  {
    path: 'test-ecosystems/container-extracted/site-packages/urllib3/__init__.py',
    content: '# urllib3\n__version__ = "2.0.4"\n'
  },
  {
    path: 'test-ecosystems/container-extracted/site-packages/urllib3-2.0.4.dist-info/METADATA',
    content: 'Metadata-Version: 2.1\nName: urllib3\nVersion: 2.0.4\n'
  },
  {
    path: 'test-ecosystems/container-extracted/site-packages/urllib3/_native.cpython-311.so',
    content: createFakeBinary(MAGIC.ELF)
  },
  
  // NuGet/.NET ecosystem
  {
    path: 'test-ecosystems/nuget-project/packages/Newtonsoft.Json/13.0.1/lib/net6.0/Newtonsoft.Json.dll',
    content: createFakeBinary(MAGIC.PE)
  },
  {
    path: 'test-ecosystems/nuget-project/packages/Newtonsoft.Json/13.0.1/Newtonsoft.Json.nuspec',
    content: `<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Newtonsoft.Json</id>
    <version>13.0.1</version>
    <authors>James Newton-King</authors>
  </metadata>
</package>`
  },
  {
    path: 'test-ecosystems/nuget-project/packages/System.Text.Json/6.0.0/lib/net6.0/System.Text.Json.dll',
    content: createFakeBinary(MAGIC.PE)
  },
  
  // Debian/Ubuntu (dpkg) ecosystem
  {
    path: 'test-ecosystems/debian-container/var/lib/dpkg/status',
    content: `Package: libssl1.1
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 4124
Maintainer: Ubuntu Developers
Architecture: amd64
Multi-Arch: same
Source: openssl
Version: 1.1.1f-1ubuntu2.20
Depends: libc6 (>= 2.25)
Description: Secure Sockets Layer toolkit - shared libraries

Package: zlib1g
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 163
Maintainer: Ubuntu Developers
Architecture: amd64
Multi-Arch: same
Version: 1:1.2.11.dfsg-2ubuntu1.5
Depends: libc6 (>= 2.4)
Description: compression library - runtime

Package: libcurl4
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 744
Maintainer: Ubuntu Developers
Architecture: amd64
Multi-Arch: same
Source: curl
Version: 7.68.0-1ubuntu2.18
Depends: libc6 (>= 2.17), libnghttp2-14, libssl1.1, zlib1g
Description: easy-to-use client-side URL transfer library
`
  },
  {
    // Note: On real Debian, filename would be libssl1.1:amd64.list but : is not valid on Windows
    path: 'test-ecosystems/debian-container/var/lib/dpkg/info/libssl1.1.list',
    content: `/usr/lib/x86_64-linux-gnu/libssl.so.1.1
/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1
`
  },
  {
    path: 'test-ecosystems/debian-container/var/lib/dpkg/info/zlib1g.list',
    content: `/usr/lib/x86_64-linux-gnu/libz.so.1.2.11
/usr/lib/x86_64-linux-gnu/libz.so.1
`
  },
  {
    path: 'test-ecosystems/debian-container/var/lib/dpkg/info/libcurl4.list',
    content: `/usr/lib/x86_64-linux-gnu/libcurl.so.4.6.0
/usr/lib/x86_64-linux-gnu/libcurl.so.4
`
  },
  {
    path: 'test-ecosystems/debian-container/usr/lib/x86_64-linux-gnu/libssl.so.1.1',
    content: createFakeBinary(MAGIC.ELF)
  },
  {
    path: 'test-ecosystems/debian-container/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1',
    content: createFakeBinary(MAGIC.ELF)
  },
  {
    path: 'test-ecosystems/debian-container/usr/lib/x86_64-linux-gnu/libz.so.1.2.11',
    content: createFakeBinary(MAGIC.ELF)
  },
  {
    path: 'test-ecosystems/debian-container/usr/lib/x86_64-linux-gnu/libcurl.so.4.6.0',
    content: createFakeBinary(MAGIC.ELF)
  },
  
  // Alpine (apk) ecosystem
  {
    path: 'test-ecosystems/alpine-container/lib/apk/db/installed',
    content: `C:Q1someChecksum=
P:musl
V:1.2.3-r4
A:x86_64
S:383152
I:622592
T:the musl c library (libc) implementation
U:https://musl.libc.org/
L:MIT
o:musl
m:Timo Teräs <timo.teras@iki.fi>
t:1678901234
c:abc123
D:
p:so:libc.musl-x86_64.so.1=1
F:lib
R:libc.musl-x86_64.so.1
a:0:0:755
Z:Q1abc123=
F:lib
R:ld-musl-x86_64.so.1
a:0:0:755
Z:Q1def456=

C:Q2anotherChecksum=
P:openssl
V:3.0.8-r3
A:x86_64
S:2847632
I:7921664
T:toolkit for TLS/SSL
U:https://www.openssl.org/
L:Apache-2.0
o:openssl
m:Ariadne Conill <ariadne@dereferenced.org>
t:1678902345
c:def456
D:so:libc.musl-x86_64.so.1 so:libcrypto.so.3
p:so:libssl.so.3=3.0 so:libcrypto.so.3=3.0
F:usr/lib
R:libssl.so.3
a:0:0:755
Z:Q2ghi789=
F:usr/lib
R:libcrypto.so.3
a:0:0:755
Z:Q2jkl012=

C:Q3thirdChecksum=
P:curl
V:8.1.2-r0
A:x86_64
S:243456
I:507904
T:URL retrival utility and library
U:https://curl.se/
L:MIT
o:curl
m:Natanael Copa <ncopa@alpinelinux.org>
t:1678903456
c:ghi789
D:so:libc.musl-x86_64.so.1 so:libcrypto.so.3 so:libssl.so.3
p:so:libcurl.so.4=4
F:usr/lib
R:libcurl.so.4
a:0:0:755
Z:Q3mno345=
`
  },
  {
    path: 'test-ecosystems/alpine-container/lib/libc.musl-x86_64.so.1',
    content: createFakeBinary(MAGIC.ELF)
  },
  {
    path: 'test-ecosystems/alpine-container/usr/lib/libssl.so.3',
    content: createFakeBinary(MAGIC.ELF)
  },
  {
    path: 'test-ecosystems/alpine-container/usr/lib/libcrypto.so.3',
    content: createFakeBinary(MAGIC.ELF)
  },
  {
    path: 'test-ecosystems/alpine-container/usr/lib/libcurl.so.4',
    content: createFakeBinary(MAGIC.ELF)
  },
  
  // RPM (RHEL/CentOS/Fedora) ecosystem
  {
    path: 'test-ecosystems/rpm-container/var/lib/rpm/.rpm.lock',
    content: ''  // Marker file to indicate RPM-based system
  },
  {
    path: 'test-ecosystems/rpm-container/usr/lib64/libssl.so.1.1',
    content: createFakeBinary(MAGIC.ELF)
  },
  {
    path: 'test-ecosystems/rpm-container/usr/lib64/libcrypto.so.1.1',
    content: createFakeBinary(MAGIC.ELF)
  },
  {
    path: 'test-ecosystems/rpm-container/usr/lib64/libcurl.so.4',
    content: createFakeBinary(MAGIC.ELF)
  },
  {
    path: 'test-ecosystems/rpm-container/usr/lib64/libz.so.1',
    content: createFakeBinary(MAGIC.ELF)
  },
  {
    path: 'test-ecosystems/rpm-container/usr/lib64/libstdc++.so.6',
    content: createFakeBinary(MAGIC.ELF)
  },
];

console.log('Creating test binary files...\n');

for (const file of testFiles) {
  const filePath = path.join(__dirname, file.path);
  const dir = path.dirname(filePath);
  
  // Ensure directory exists
  fs.mkdirSync(dir, { recursive: true });
  
  // Write file
  if (Buffer.isBuffer(file.content)) {
    fs.writeFileSync(filePath, file.content);
  } else {
    fs.writeFileSync(filePath, file.content, 'utf8');
  }
  
  console.log(`  ✓ ${file.path}`);
}

console.log(`\nCreated ${testFiles.length} test files.`);
console.log('\nYou can now test the scanner with:');
console.log('');
console.log('  # Language package managers:');
console.log('  node scanner.js test-ecosystems/npm-project');
console.log('  node scanner.js test-ecosystems/pip-project --ecosystem pip');
console.log('  node scanner.js test-ecosystems/maven-project --ecosystem maven');
console.log('  node scanner.js test-ecosystems/cargo-project --ecosystem cargo');
console.log('  node scanner.js test-ecosystems/go-project --ecosystem go');
console.log('  node scanner.js test-ecosystems/nuget-project --ecosystem nuget');
console.log('');
console.log('  # Linux package managers (container scanning):');
console.log('  node scanner.js test-ecosystems/debian-container --ecosystem dpkg');
console.log('  node scanner.js test-ecosystems/alpine-container --ecosystem apk');
console.log('  node scanner.js test-ecosystems/rpm-container --ecosystem rpm');
console.log('');
console.log('  # Multi-ecosystem:');
console.log('  node scanner.js test-ecosystems/container-extracted --ecosystem npm,pip');
console.log('  node scanner.js test-ecosystems  # auto-detect all');
console.log('');
console.log('  # List all supported ecosystems:');
console.log('  node scanner.js --list-ecosystems');