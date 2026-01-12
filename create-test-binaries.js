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
console.log('  node scanner.js test-ecosystems/npm-project');
console.log('  node scanner.js test-ecosystems/pip-project --ecosystem pip');
console.log('  node scanner.js test-ecosystems/maven-project --ecosystem maven');
console.log('  node scanner.js test-ecosystems/cargo-project --ecosystem cargo');
console.log('  node scanner.js test-ecosystems/go-project --ecosystem go');
console.log('  node scanner.js test-ecosystems/container-extracted --ecosystem npm,pip');
console.log('  node scanner.js test-ecosystems  # auto-detect all');
