/**
 * Ecosystem Configuration Module
 * 
 * Defines package manager ecosystems and their metadata extraction strategies.
 * Each ecosystem specifies:
 * - directories: where packages are installed
 * - tagPrefix: tag prefix for UnknownCyber (SW_<pm>/)
 * - findPackageInfo: function to extract package name/version from file path
 */

const fs = require('fs');
const path = require('path');

/**
 * NPM/Node.js ecosystem
 * Packages in node_modules/, metadata in package.json
 */
function findNpmPackageInfo(filePath, rootDir) {
  let dir = path.dirname(filePath);
  
  while (dir.length >= rootDir.length) {
    const packageJsonPath = path.join(dir, 'package.json');
    
    if (fs.existsSync(packageJsonPath)) {
      try {
        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        const relativePath = path.relative(rootDir, dir);
        
        return {
          name: packageJson.name || path.basename(dir),
          version: packageJson.version || 'unknown',
          path: dir,
          relativePath: relativePath
        };
      } catch (err) {
        // Continue searching up
      }
    }
    
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  
  return null;
}

/**
 * Python/pip ecosystem
 * Packages in site-packages/ or dist-packages/
 * Metadata in *.dist-info/METADATA or *.egg-info/PKG-INFO
 */
function findPipPackageInfo(filePath, rootDir) {
  // Get the relative path from root
  const relativePath = path.relative(rootDir, filePath);
  const parts = relativePath.split(path.sep);
  
  if (parts.length < 1) return null;
  
  // Look for dist-info or egg-info directories at the package level
  const entries = fs.readdirSync(rootDir);
  
  // First, try to find which package this file belongs to by checking dist-info
  for (const entry of entries) {
    const entryPath = path.join(rootDir, entry);
    const stat = fs.statSync(entryPath);
    
    if (stat.isDirectory()) {
      // Check if this is a dist-info directory
      if (entry.endsWith('.dist-info')) {
        const metadataPath = path.join(entryPath, 'METADATA');
        const recordPath = path.join(entryPath, 'RECORD');
        
        // Check if this dist-info owns the file by looking at RECORD
        if (fs.existsSync(recordPath)) {
          try {
            const record = fs.readFileSync(recordPath, 'utf8');
            const fileRelative = relativePath.replace(/\\/g, '/');
            
            if (record.includes(fileRelative) || record.includes(parts[0] + '/')) {
              // This dist-info owns this file, parse METADATA
              if (fs.existsSync(metadataPath)) {
                const metadata = fs.readFileSync(metadataPath, 'utf8');
                const nameMatch = metadata.match(/^Name:\s*(.+)$/m);
                const versionMatch = metadata.match(/^Version:\s*(.+)$/m);
                
                return {
                  name: nameMatch ? nameMatch[1].trim() : entry.replace('.dist-info', ''),
                  version: versionMatch ? versionMatch[1].trim() : 'unknown',
                  path: entryPath,
                  relativePath: parts[0]
                };
              }
            }
          } catch (err) {
            // Continue
          }
        }
        
        // Fallback: match by directory name prefix
        const distInfoName = entry.replace('.dist-info', '').split('-')[0].toLowerCase();
        if (parts[0].toLowerCase() === distInfoName || 
            parts[0].toLowerCase().replace(/_/g, '-') === distInfoName) {
          if (fs.existsSync(metadataPath)) {
            try {
              const metadata = fs.readFileSync(metadataPath, 'utf8');
              const nameMatch = metadata.match(/^Name:\s*(.+)$/m);
              const versionMatch = metadata.match(/^Version:\s*(.+)$/m);
              
              return {
                name: nameMatch ? nameMatch[1].trim() : distInfoName,
                version: versionMatch ? versionMatch[1].trim() : 'unknown',
                path: path.join(rootDir, parts[0]),
                relativePath: parts[0]
              };
            } catch (err) {
              // Continue
            }
          }
        }
      }
      
      // Check for egg-info
      if (entry.endsWith('.egg-info')) {
        const pkgInfoPath = path.join(entryPath, 'PKG-INFO');
        const eggName = entry.replace('.egg-info', '').split('-')[0].toLowerCase();
        
        if (parts[0].toLowerCase() === eggName ||
            parts[0].toLowerCase().replace(/_/g, '-') === eggName) {
          if (fs.existsSync(pkgInfoPath)) {
            try {
              const pkgInfo = fs.readFileSync(pkgInfoPath, 'utf8');
              const nameMatch = pkgInfo.match(/^Name:\s*(.+)$/m);
              const versionMatch = pkgInfo.match(/^Version:\s*(.+)$/m);
              
              return {
                name: nameMatch ? nameMatch[1].trim() : eggName,
                version: versionMatch ? versionMatch[1].trim() : 'unknown',
                path: path.join(rootDir, parts[0]),
                relativePath: parts[0]
              };
            } catch (err) {
              // Continue
            }
          }
        }
      }
    }
  }
  
  // Fallback: use the top-level directory name as package name
  if (parts[0] && !parts[0].endsWith('.dist-info') && !parts[0].endsWith('.egg-info')) {
    return {
      name: parts[0],
      version: 'unknown',
      path: path.join(rootDir, parts[0]),
      relativePath: parts[0]
    };
  }
  
  return null;
}

/**
 * Maven/Java ecosystem
 * Packages typically in .m2/repository/ or lib/
 * Structure: groupId/artifactId/version/artifactId-version.jar
 */
function findMavenPackageInfo(filePath, rootDir) {
  const relativePath = path.relative(rootDir, filePath);
  const parts = relativePath.split(path.sep);
  
  // Maven repository structure: groupId.parts/artifactId/version/file
  // e.g., org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar
  
  if (parts.length >= 3) {
    // Try to find version directory (usually contains numbers and dots)
    for (let i = parts.length - 2; i >= 0; i--) {
      if (/^\d+(\.\d+)*/.test(parts[i])) {
        // Found version, artifact is previous, group is everything before
        const version = parts[i];
        const artifactId = parts[i - 1] || 'unknown';
        const groupId = parts.slice(0, i - 1).join('.');
        
        return {
          name: groupId ? `${groupId}:${artifactId}` : artifactId,
          version: version,
          path: path.join(rootDir, ...parts.slice(0, i + 1)),
          relativePath: parts.slice(0, i + 1).join(path.sep)
        };
      }
    }
  }
  
  // Fallback: check for pom.xml in directory
  let dir = path.dirname(filePath);
  while (dir.length >= rootDir.length) {
    const pomPath = path.join(dir, 'pom.xml');
    if (fs.existsSync(pomPath)) {
      try {
        const pom = fs.readFileSync(pomPath, 'utf8');
        const artifactMatch = pom.match(/<artifactId>([^<]+)<\/artifactId>/);
        const versionMatch = pom.match(/<version>([^<]+)<\/version>/);
        const groupMatch = pom.match(/<groupId>([^<]+)<\/groupId>/);
        
        const artifactId = artifactMatch ? artifactMatch[1] : path.basename(dir);
        const groupId = groupMatch ? groupMatch[1] : '';
        
        return {
          name: groupId ? `${groupId}:${artifactId}` : artifactId,
          version: versionMatch ? versionMatch[1] : 'unknown',
          path: dir,
          relativePath: path.relative(rootDir, dir)
        };
      } catch (err) {
        // Continue
      }
    }
    
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  
  // Final fallback
  return {
    name: parts[0] || 'unknown',
    version: 'unknown',
    path: path.join(rootDir, parts[0] || ''),
    relativePath: parts[0] || ''
  };
}

/**
 * Cargo/Rust ecosystem
 * Packages in target/release/ or target/debug/
 * Metadata in Cargo.toml
 */
function findCargoPackageInfo(filePath, rootDir) {
  // Look for Cargo.toml in parent directories
  let dir = path.dirname(filePath);
  
  // First check the root for Cargo.toml
  const rootCargoPath = path.join(rootDir, '..', 'Cargo.toml');
  if (fs.existsSync(rootCargoPath)) {
    try {
      const cargo = fs.readFileSync(rootCargoPath, 'utf8');
      const nameMatch = cargo.match(/^\s*name\s*=\s*"([^"]+)"/m);
      const versionMatch = cargo.match(/^\s*version\s*=\s*"([^"]+)"/m);
      
      return {
        name: nameMatch ? nameMatch[1] : 'unknown',
        version: versionMatch ? versionMatch[1] : 'unknown',
        path: path.dirname(rootCargoPath),
        relativePath: path.relative(rootDir, filePath)
      };
    } catch (err) {
      // Continue
    }
  }
  
  while (dir.length >= rootDir.length) {
    const cargoPath = path.join(dir, 'Cargo.toml');
    if (fs.existsSync(cargoPath)) {
      try {
        const cargo = fs.readFileSync(cargoPath, 'utf8');
        const nameMatch = cargo.match(/^\s*name\s*=\s*"([^"]+)"/m);
        const versionMatch = cargo.match(/^\s*version\s*=\s*"([^"]+)"/m);
        
        return {
          name: nameMatch ? nameMatch[1] : path.basename(dir),
          version: versionMatch ? versionMatch[1] : 'unknown',
          path: dir,
          relativePath: path.relative(rootDir, dir)
        };
      } catch (err) {
        // Continue
      }
    }
    
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  
  // Fallback: use filename as package name (common for Rust binaries)
  const filename = path.basename(filePath);
  const name = filename.replace(/\.(exe|dll|so|dylib)$/i, '');
  
  return {
    name: name,
    version: 'unknown',
    path: path.dirname(filePath),
    relativePath: path.relative(rootDir, filePath)
  };
}

/**
 * Go modules ecosystem
 * Packages in vendor/ or Go module cache
 * Metadata in go.mod
 */
function findGoPackageInfo(filePath, rootDir) {
  const relativePath = path.relative(rootDir, filePath);
  const parts = relativePath.split(path.sep);
  
  // Go vendor structure: vendor/github.com/user/repo/...
  // or module cache: pkg/mod/github.com/user/repo@v1.2.3/...
  
  // Check for version in path (e.g., @v1.2.3)
  for (let i = 0; i < parts.length; i++) {
    if (parts[i].includes('@v')) {
      const [name, version] = parts[i].split('@');
      const modulePath = parts.slice(0, i).join('/') + '/' + name;
      
      return {
        name: modulePath,
        version: version.replace(/^v/, ''),
        path: path.join(rootDir, ...parts.slice(0, i + 1)),
        relativePath: parts.slice(0, i + 1).join(path.sep)
      };
    }
  }
  
  // Look for go.mod
  let dir = path.dirname(filePath);
  while (dir.length >= rootDir.length) {
    const goModPath = path.join(dir, 'go.mod');
    if (fs.existsSync(goModPath)) {
      try {
        const goMod = fs.readFileSync(goModPath, 'utf8');
        const moduleMatch = goMod.match(/^module\s+(.+)$/m);
        
        return {
          name: moduleMatch ? moduleMatch[1].trim() : path.basename(dir),
          version: 'unknown',
          path: dir,
          relativePath: path.relative(rootDir, dir)
        };
      } catch (err) {
        // Continue
      }
    }
    
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  
  // Fallback: construct module path from directory structure
  // vendor/github.com/user/repo -> github.com/user/repo
  if (parts.length >= 3 && (parts[0].includes('.') || parts[1]?.includes('.'))) {
    return {
      name: parts.slice(0, Math.min(3, parts.length)).join('/'),
      version: 'unknown',
      path: path.join(rootDir, ...parts.slice(0, 3)),
      relativePath: parts.slice(0, 3).join(path.sep)
    };
  }
  
  return {
    name: parts[0] || 'unknown',
    version: 'unknown',
    path: path.join(rootDir, parts[0] || ''),
    relativePath: parts[0] || ''
  };
}

/**
 * Ruby gems ecosystem
 * Packages in vendor/bundle/ or gems directory
 * Metadata in *.gemspec
 */
function findRubyPackageInfo(filePath, rootDir) {
  const relativePath = path.relative(rootDir, filePath);
  const parts = relativePath.split(path.sep);
  
  // Ruby bundle structure: ruby/3.0.0/gems/gemname-1.2.3/...
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === 'gems' && i + 1 < parts.length) {
      const gemDir = parts[i + 1];
      // Parse gemname-version format
      const match = gemDir.match(/^(.+?)-(\d+\.\d+.*)$/);
      if (match) {
        return {
          name: match[1],
          version: match[2],
          path: path.join(rootDir, ...parts.slice(0, i + 2)),
          relativePath: parts.slice(0, i + 2).join(path.sep)
        };
      }
    }
  }
  
  // Look for gemspec files
  let dir = path.dirname(filePath);
  while (dir.length >= rootDir.length) {
    try {
      const entries = fs.readdirSync(dir);
      const gemspec = entries.find(e => e.endsWith('.gemspec'));
      if (gemspec) {
        const gemspecPath = path.join(dir, gemspec);
        const content = fs.readFileSync(gemspecPath, 'utf8');
        const nameMatch = content.match(/\.name\s*=\s*['"]([^'"]+)['"]/);
        const versionMatch = content.match(/\.version\s*=\s*['"]([^'"]+)['"]/);
        
        return {
          name: nameMatch ? nameMatch[1] : gemspec.replace('.gemspec', ''),
          version: versionMatch ? versionMatch[1] : 'unknown',
          path: dir,
          relativePath: path.relative(rootDir, dir)
        };
      }
    } catch (err) {
      // Continue
    }
    
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  
  return {
    name: parts[0] || 'unknown',
    version: 'unknown',
    path: path.join(rootDir, parts[0] || ''),
    relativePath: parts[0] || ''
  };
}

/**
 * Generic/container filesystem
 * For scanning arbitrary directories without package attribution
 */
function findGenericPackageInfo(filePath, rootDir) {
  const relativePath = path.relative(rootDir, filePath);
  const parts = relativePath.split(path.sep);
  
  return {
    name: parts[0] || path.basename(filePath),
    version: 'unknown',
    path: path.join(rootDir, parts[0] || ''),
    relativePath: parts[0] || ''
  };
}

/**
 * Ecosystem definitions
 */
const ECOSYSTEMS = {
  npm: {
    name: 'npm',
    displayName: 'NPM/Node.js',
    directories: ['node_modules'],
    tagPrefix: 'SW_npm',
    findPackageInfo: findNpmPackageInfo,
    description: 'Node.js packages installed via npm/yarn/pnpm'
  },
  pip: {
    name: 'pip',
    displayName: 'Python/pip',
    directories: ['site-packages', 'dist-packages', 'Lib/site-packages'],
    tagPrefix: 'SW_pip',
    findPackageInfo: findPipPackageInfo,
    description: 'Python packages installed via pip'
  },
  maven: {
    name: 'maven',
    displayName: 'Maven/Java',
    directories: ['.m2/repository', 'lib', 'target/dependency'],
    tagPrefix: 'SW_maven',
    findPackageInfo: findMavenPackageInfo,
    description: 'Java packages from Maven repository'
  },
  cargo: {
    name: 'cargo',
    displayName: 'Cargo/Rust',
    directories: ['target/release', 'target/debug'],
    tagPrefix: 'SW_cargo',
    findPackageInfo: findCargoPackageInfo,
    description: 'Rust binaries built with Cargo'
  },
  go: {
    name: 'go',
    displayName: 'Go Modules',
    directories: ['vendor', 'pkg/mod'],
    tagPrefix: 'SW_go',
    findPackageInfo: findGoPackageInfo,
    description: 'Go modules and vendored dependencies'
  },
  ruby: {
    name: 'ruby',
    displayName: 'Ruby Gems',
    directories: ['vendor/bundle', 'gems'],
    tagPrefix: 'SW_ruby',
    findPackageInfo: findRubyPackageInfo,
    description: 'Ruby gems installed via Bundler'
  },
  generic: {
    name: 'generic',
    displayName: 'Generic',
    directories: ['.'],
    tagPrefix: 'SW_generic',
    findPackageInfo: findGenericPackageInfo,
    description: 'Generic directory scan without package attribution'
  }
};

/**
 * Detect which ecosystems are present in a directory
 * @param {string} targetDir - Directory to scan
 * @returns {string[]} - Array of detected ecosystem names
 */
function detectEcosystems(targetDir) {
  const detected = [];
  
  for (const [name, config] of Object.entries(ECOSYSTEMS)) {
    if (name === 'generic') continue; // Don't auto-detect generic
    
    for (const dir of config.directories) {
      const checkPath = path.join(targetDir, dir);
      if (fs.existsSync(checkPath)) {
        detected.push(name);
        break;
      }
    }
  }
  
  return detected;
}

/**
 * Get ecosystem configuration by name
 * @param {string} name - Ecosystem name
 * @returns {object|null} - Ecosystem configuration
 */
function getEcosystem(name) {
  return ECOSYSTEMS[name] || null;
}

/**
 * Get all available ecosystem names
 * @returns {string[]} - Array of ecosystem names
 */
function getAvailableEcosystems() {
  return Object.keys(ECOSYSTEMS);
}

/**
 * Find the package directory for an ecosystem in a target directory
 * @param {string} targetDir - Target directory
 * @param {string} ecosystemName - Ecosystem name
 * @returns {string|null} - Path to package directory or null
 */
function findEcosystemDirectory(targetDir, ecosystemName) {
  const ecosystem = ECOSYSTEMS[ecosystemName];
  if (!ecosystem) return null;
  
  for (const dir of ecosystem.directories) {
    const checkPath = path.join(targetDir, dir);
    if (fs.existsSync(checkPath)) {
      return checkPath;
    }
  }
  
  return null;
}

module.exports = {
  ECOSYSTEMS,
  detectEcosystems,
  getEcosystem,
  getAvailableEcosystems,
  findEcosystemDirectory,
  // Export individual finders for testing
  findNpmPackageInfo,
  findPipPackageInfo,
  findMavenPackageInfo,
  findCargoPackageInfo,
  findGoPackageInfo,
  findRubyPackageInfo,
  findGenericPackageInfo
};
