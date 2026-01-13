#!/usr/bin/env node
/**
 * License Compliance Checker for software packages
 * Scans node_modules and checks licenses against a configurable policy
 */

const fs = require('fs');
const path = require('path');

// Default policy - can be overridden by user-provided policy file
const DEFAULT_POLICY = {
  // Licenses that are always allowed
  allowed: [
    'MIT',
    'Apache-2.0',
    'BSD-2-Clause',
    'BSD-3-Clause',
    'ISC',
    '0BSD',
    'CC0-1.0',
    'Unlicense',
    'WTFPL',
    'CC-BY-3.0',
    'CC-BY-4.0',
    'Zlib',
    'BlueOak-1.0.0'
  ],
  
  // Licenses that generate warnings (may need review)
  warning: [
    'LGPL-2.0',
    'LGPL-2.1',
    'LGPL-3.0',
    'LGPL-2.0-only',
    'LGPL-2.1-only',
    'LGPL-3.0-only',
    'LGPL-2.0-or-later',
    'LGPL-2.1-or-later',
    'LGPL-3.0-or-later',
    'MPL-2.0',
    'EPL-1.0',
    'EPL-2.0',
    'CDDL-1.0',
    'CDDL-1.1',
    'Artistic-2.0',
    'OSL-3.0',
    'CC-BY-SA-3.0',
    'CC-BY-SA-4.0'
  ],
  
  // Licenses that are denied (block pipeline)
  denied: [
    'GPL-2.0',
    'GPL-2.0-only',
    'GPL-2.0-or-later',
    'GPL-3.0',
    'GPL-3.0-only',
    'GPL-3.0-or-later',
    'AGPL-1.0',
    'AGPL-3.0',
    'AGPL-3.0-only',
    'AGPL-3.0-or-later',
    'SSPL-1.0',
    'CC-BY-NC-1.0',
    'CC-BY-NC-2.0',
    'CC-BY-NC-3.0',
    'CC-BY-NC-4.0',
    'CC-BY-NC-SA-1.0',
    'CC-BY-NC-SA-2.0',
    'CC-BY-NC-SA-3.0',
    'CC-BY-NC-SA-4.0',
    'CC-BY-NC-ND-1.0',
    'CC-BY-NC-ND-2.0',
    'CC-BY-NC-ND-3.0',
    'CC-BY-NC-ND-4.0'
  ],
  
  // How to handle packages with unknown/missing licenses
  unknownPolicy: 'warning',  // 'allowed', 'warning', 'denied'
  
  // Package-specific overrides (useful for false positives or reviewed packages)
  overrides: {
    // Example: "package-name": "allowed"
  }
};

/**
 * Normalize license identifier to SPDX format
 */
function normalizeLicense(license) {
  if (!license) return null;
  
  // Handle common variations
  const normalizations = {
    'MIT': 'MIT',
    'MIT License': 'MIT',
    'MIT/X11': 'MIT',
    'Apache 2.0': 'Apache-2.0',
    'Apache-2': 'Apache-2.0',
    'Apache License 2.0': 'Apache-2.0',
    'Apache License, Version 2.0': 'Apache-2.0',
    'BSD': 'BSD-3-Clause',
    'BSD-2': 'BSD-2-Clause',
    'BSD-3': 'BSD-3-Clause',
    'BSD 2-Clause': 'BSD-2-Clause',
    'BSD 3-Clause': 'BSD-3-Clause',
    'ISC License': 'ISC',
    'GPL': 'GPL-3.0',
    'GPL-2': 'GPL-2.0',
    'GPL-3': 'GPL-3.0',
    'GPLv2': 'GPL-2.0',
    'GPLv3': 'GPL-3.0',
    'LGPL': 'LGPL-3.0',
    'LGPLv2': 'LGPL-2.0',
    'LGPLv2.1': 'LGPL-2.1',
    'LGPLv3': 'LGPL-3.0',
    'AGPL': 'AGPL-3.0',
    'AGPLv3': 'AGPL-3.0',
    'MPL': 'MPL-2.0',
    'MPL 2.0': 'MPL-2.0',
    'CC0': 'CC0-1.0',
    'Public Domain': 'Unlicense',
    'UNLICENSED': 'UNLICENSED',
    'SEE LICENSE IN LICENSE': 'Custom',
    'SEE LICENSE IN LICENSE.md': 'Custom',
    'SEE LICENSE': 'Custom'
  };
  
  const upper = license.toUpperCase().trim();
  
  for (const [key, value] of Object.entries(normalizations)) {
    if (key.toUpperCase() === upper) {
      return value;
    }
  }
  
  // Return as-is if no normalization found
  return license.trim();
}

/**
 * Parse license from package.json
 */
function parseLicense(pkg) {
  // Standard license field (SPDX identifier)
  if (typeof pkg.license === 'string') {
    return normalizeLicense(pkg.license);
  }
  
  // Object format (deprecated but still used)
  if (pkg.license && typeof pkg.license === 'object' && pkg.license.type) {
    return normalizeLicense(pkg.license.type);
  }
  
  // Legacy licenses array
  if (Array.isArray(pkg.licenses)) {
    const licenses = pkg.licenses
      .map(l => typeof l === 'string' ? l : l.type)
      .filter(Boolean)
      .map(normalizeLicense);
    return licenses.length > 0 ? licenses.join(' OR ') : null;
  }
  
  return null;
}

/**
 * Classify a license based on policy
 */
function classifyLicense(license, policy) {
  if (!license || license === 'UNLICENSED' || license === 'Custom') {
    return policy.unknownPolicy || 'warning';
  }
  
  // Handle SPDX expressions (e.g., "MIT OR Apache-2.0")
  const licenses = license.split(/\s+OR\s+|\s+AND\s+/i).map(l => l.trim().replace(/[()]/g, ''));
  
  // If ANY license in expression is denied, it's denied
  for (const l of licenses) {
    if (policy.denied?.some(d => d.toLowerCase() === l.toLowerCase())) {
      return 'denied';
    }
  }
  
  // If ALL licenses in expression are allowed, it's allowed
  const allAllowed = licenses.every(l => 
    policy.allowed?.some(a => a.toLowerCase() === l.toLowerCase())
  );
  if (allAllowed) {
    return 'allowed';
  }
  
  // If any license is in warning list
  for (const l of licenses) {
    if (policy.warning?.some(w => w.toLowerCase() === l.toLowerCase())) {
      return 'warning';
    }
  }
  
  // Unknown license
  return policy.unknownPolicy || 'warning';
}

/**
 * Scan node_modules for licenses
 */
function scanLicenses(nodeModulesPath, policy) {
  const results = {
    total: 0,
    allowed: [],
    warning: [],
    denied: [],
    unknown: [],
    byLicense: {}
  };
  
  if (!fs.existsSync(nodeModulesPath)) {
    console.error(`node_modules not found at: ${nodeModulesPath}`);
    return results;
  }
  
  function scanPackage(pkgPath, depth = 0) {
    const packageJsonPath = path.join(pkgPath, 'package.json');
    
    if (!fs.existsSync(packageJsonPath)) {
      return;
    }
    
    try {
      const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
      const license = parseLicense(pkg);
      const packageName = pkg.name || path.basename(pkgPath);
      const packageVersion = pkg.version || 'unknown';
      
      // Check for package-specific override
      let classification;
      if (policy.overrides && policy.overrides[packageName]) {
        classification = policy.overrides[packageName];
      } else {
        classification = classifyLicense(license, policy);
      }
      
      const entry = {
        name: packageName,
        version: packageVersion,
        license: license || 'UNKNOWN',
        path: pkgPath.replace(nodeModulesPath, 'node_modules'),
        classification
      };
      
      results.total++;
      
      // Track by license
      const licenseKey = license || 'UNKNOWN';
      if (!results.byLicense[licenseKey]) {
        results.byLicense[licenseKey] = [];
      }
      results.byLicense[licenseKey].push(entry);
      
      // Track by classification
      switch (classification) {
        case 'allowed':
          results.allowed.push(entry);
          break;
        case 'warning':
          results.warning.push(entry);
          break;
        case 'denied':
          results.denied.push(entry);
          break;
        default:
          results.unknown.push(entry);
      }
      
      // Scan nested node_modules (for nested dependencies)
      const nestedNodeModules = path.join(pkgPath, 'node_modules');
      if (fs.existsSync(nestedNodeModules) && depth < 10) {
        scanDirectory(nestedNodeModules, depth + 1);
      }
      
    } catch (err) {
      // Skip packages with invalid package.json
    }
  }
  
  function scanDirectory(dirPath, depth = 0) {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      
      const fullPath = path.join(dirPath, entry.name);
      
      // Handle scoped packages (@org/pkg)
      if (entry.name.startsWith('@')) {
        const scopedEntries = fs.readdirSync(fullPath, { withFileTypes: true });
        for (const scopedEntry of scopedEntries) {
          if (scopedEntry.isDirectory()) {
            scanPackage(path.join(fullPath, scopedEntry.name), depth);
          }
        }
      } else {
        scanPackage(fullPath, depth);
      }
    }
  }
  
  scanDirectory(nodeModulesPath);
  
  return results;
}

/**
 * Load policy from file
 */
function loadPolicy(policyPath) {
  if (!policyPath) {
    return DEFAULT_POLICY;
  }
  
  // Handle preset names
  const presets = {
    'permissive': DEFAULT_POLICY,
    'strict': {
      ...DEFAULT_POLICY,
      warning: [...DEFAULT_POLICY.warning, ...DEFAULT_POLICY.denied],
      denied: [],
      unknownPolicy: 'denied'
    },
    'copyleft-ok': {
      ...DEFAULT_POLICY,
      allowed: [...DEFAULT_POLICY.allowed, 'GPL-2.0', 'GPL-3.0', 'LGPL-2.1', 'LGPL-3.0'],
      denied: DEFAULT_POLICY.denied.filter(l => !l.startsWith('GPL') && !l.startsWith('LGPL'))
    }
  };
  
  if (presets[policyPath]) {
    return presets[policyPath];
  }
  
  // Load from file
  if (fs.existsSync(policyPath)) {
    try {
      const customPolicy = JSON.parse(fs.readFileSync(policyPath, 'utf-8'));
      return { ...DEFAULT_POLICY, ...customPolicy };
    } catch (err) {
      console.error(`Error loading policy file: ${err.message}`);
      return DEFAULT_POLICY;
    }
  }
  
  console.warn(`Policy file not found: ${policyPath}, using default`);
  return DEFAULT_POLICY;
}

/**
 * Generate GitHub annotations
 */
function emitAnnotations(results) {
  for (const pkg of results.denied) {
    console.log(`::error title=Denied License::${pkg.name}@${pkg.version} uses ${pkg.license} - this license is not allowed`);
  }
  
  for (const pkg of results.warning) {
    console.log(`::warning title=License Warning::${pkg.name}@${pkg.version} uses ${pkg.license} - review recommended`);
  }
  
  for (const pkg of results.unknown) {
    console.log(`::notice title=Unknown License::${pkg.name}@${pkg.version} has no license specified`);
  }
}

/**
 * Generate summary for GITHUB_STEP_SUMMARY
 */
function generateSummary(results) {
  let output = '';
  
  output += '### 📜 License Compliance Report\n\n';
  output += `| Status | Count |\n`;
  output += `|--------|-------|\n`;
  output += `| ✅ Allowed | ${results.allowed.length} |\n`;
  output += `| ⚠️ Warning | ${results.warning.length} |\n`;
  output += `| ❌ Denied | ${results.denied.length} |\n`;
  output += `| ❓ Unknown | ${results.unknown.length} |\n`;
  output += '\n';
  
  if (results.denied.length > 0) {
    output += '#### ❌ Denied Licenses\n\n';
    output += '| Package | Version | License |\n';
    output += '|---------|---------|----------|\n';
    for (const pkg of results.denied) {
      output += `| ${pkg.name} | ${pkg.version} | ${pkg.license} |\n`;
    }
    output += '\n';
  }
  
  if (results.warning.length > 0) {
    output += '#### ⚠️ Licenses Requiring Review\n\n';
    output += '| Package | Version | License |\n';
    output += '|---------|---------|----------|\n';
    for (const pkg of results.warning.slice(0, 20)) {
      output += `| ${pkg.name} | ${pkg.version} | ${pkg.license} |\n`;
    }
    if (results.warning.length > 20) {
      output += `| ... | ... | (${results.warning.length - 20} more) |\n`;
    }
    output += '\n';
  }
  
  if (results.unknown.length > 0) {
    output += '#### ❓ Unknown/Missing Licenses\n\n';
    output += '| Package | Version |\n';
    output += '|---------|----------|\n';
    for (const pkg of results.unknown.slice(0, 10)) {
      output += `| ${pkg.name} | ${pkg.version} |\n`;
    }
    if (results.unknown.length > 10) {
      output += `| ... | (${results.unknown.length - 10} more) |\n`;
    }
    output += '\n';
  }
  
  // License distribution
  output += '#### 📊 License Distribution\n\n';
  output += '| License | Count |\n';
  output += '|---------|-------|\n';
  const sortedLicenses = Object.entries(results.byLicense)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 15);
  for (const [license, packages] of sortedLicenses) {
    output += `| ${license} | ${packages.length} |\n`;
  }
  
  return output;
}

/**
 * Main CLI
 */
function main() {
  const args = process.argv.slice(2);
  
  let nodeModulesPath = 'node_modules';
  let policyPath = null;
  let outputPath = null;
  let emitGithubAnnotations = false;
  let generateGithubSummary = false;
  
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--path':
      case '-p':
        nodeModulesPath = args[++i];
        break;
      case '--policy':
        policyPath = args[++i];
        break;
      case '--output':
      case '-o':
        outputPath = args[++i];
        break;
      case '--github-annotations':
        emitGithubAnnotations = true;
        break;
      case '--github-summary':
        generateGithubSummary = true;
        break;
      case '--help':
      case '-h':
        console.log(`
License Compliance Checker

Usage: node license-checker.js [options]

Options:
  --path, -p <path>       Path to node_modules (default: ./node_modules)
  --policy <path|preset>  Policy file or preset (permissive, strict, copyleft-ok)
  --output, -o <path>     Output JSON results to file
  --github-annotations    Emit GitHub Actions annotations
  --github-summary        Append to GITHUB_STEP_SUMMARY
  --help, -h              Show this help

Policy File Format:
  {
    "allowed": ["MIT", "Apache-2.0", ...],
    "warning": ["LGPL-3.0", "MPL-2.0", ...],
    "denied": ["GPL-3.0", "AGPL-3.0", ...],
    "unknownPolicy": "warning",
    "overrides": {
      "package-name": "allowed"
    }
  }
`);
        process.exit(0);
    }
  }
  
  console.log('\n=== License Compliance Check ===\n');
  
  const policy = loadPolicy(policyPath);
  console.log(`Policy: ${policyPath || 'default (permissive)'}`);
  console.log(`Scanning: ${nodeModulesPath}\n`);
  
  const results = scanLicenses(nodeModulesPath, policy);
  
  // Console summary
  console.log(`Total packages scanned: ${results.total}`);
  console.log(`  ✅ Allowed: ${results.allowed.length}`);
  console.log(`  ⚠️  Warning: ${results.warning.length}`);
  console.log(`  ❌ Denied: ${results.denied.length}`);
  console.log(`  ❓ Unknown: ${results.unknown.length}`);
  
  // Detailed output for denied packages
  if (results.denied.length > 0) {
    console.log('\n❌ DENIED LICENSES:');
    for (const pkg of results.denied) {
      console.log(`  - ${pkg.name}@${pkg.version}: ${pkg.license}`);
    }
  }
  
  // GitHub annotations
  if (emitGithubAnnotations) {
    emitAnnotations(results);
  }
  
  // GitHub summary
  if (generateGithubSummary) {
    const summaryPath = process.env.GITHUB_STEP_SUMMARY;
    if (summaryPath) {
      fs.appendFileSync(summaryPath, generateSummary(results));
    } else {
      console.log('\n' + generateSummary(results));
    }
  }
  
  // Save JSON output
  if (outputPath) {
    fs.writeFileSync(outputPath, JSON.stringify(results, null, 2));
    console.log(`\nResults saved to: ${outputPath}`);
  }
  
  // Output for GitHub Actions
  console.log(`\nlicense-allowed=${results.allowed.length}`);
  console.log(`license-warning=${results.warning.length}`);
  console.log(`license-denied=${results.denied.length}`);
  console.log(`license-unknown=${results.unknown.length}`);
  
  // Exit with error if denied licenses found
  if (results.denied.length > 0) {
    process.exit(1);
  }
  
  process.exit(0);
}

// Export for use as module
module.exports = {
  scanLicenses,
  loadPolicy,
  classifyLicense,
  parseLicense,
  normalizeLicense,
  DEFAULT_POLICY
};

// Run if called directly
if (require.main === module) {
  main();
}
