#!/usr/bin/env node
/**
 * Generate GitHub Actions summary report for uc-software-scan
 * Outputs to GITHUB_STEP_SUMMARY with links to UnknownCyber reports
 */

const fs = require('fs');
const path = require('path');

const UC_BASE = 'https://unknowncyber.com/files';

function makeLink(file, sha256) {
  if (sha256) {
    return `[${file}](${UC_BASE}/${sha256}/report/)`;
  }
  return file;
}

function generateHeader() {
  return '# 🛡️ UC Software Scan Report\n\n';
}

function generateScanMetrics(results) {
  let output = '';
  
  output += '## 📊 Scan Metrics\n\n';
  
  // Packages scanned
  output += '| Metric | Count |\n';
  output += '|--------|-------|\n';
  output += `| Packages scanned | ${results.totalPackages || 0} |\n`;
  output += `| Binary files found | ${results.totalBinaries || 0} |\n`;
  
  // Upload results
  if (results.uploadResults) {
    const ur = results.uploadResults;
    output += `| ✅ Uploaded | ${ur.successful?.length || 0} |\n`;
    output += `| ⏭️ Skipped (existing) | ${ur.skipped?.length || 0} |\n`;
    output += `| ❌ Failed | ${ur.failed?.length || 0} |\n`;
  }
  
  output += '\n';
  return output;
}

function generateMalwareReport(results) {
  let output = '';
  
  output += '## 🦠 Malware Report\n\n';
  
  if (!results.uploadResults?.reputations) {
    output += '✅ No violations found\n\n';
    return output;
  }
  
  const reps = results.uploadResults.reputations;
  const malwareFindings = reps.filter(r => {
    const av = r.reputation?.av;
    return av && (av.threatLevel === 'high' || av.threatLevel === 'medium');
  });
  
  if (malwareFindings.length === 0) {
    output += '✅ No violations found\n\n';
    return output;
  }
  
  output += '| File | AV Detection | Threat Level |\n';
  output += '|------|--------------|-------------|\n';
  
  malwareFindings.forEach(r => {
    const av = r.reputation.av;
    const icon = av.threatLevel === 'high' ? '🔴' : '🟠';
    output += `| ${makeLink(r.file, r.sha256)} | ${av.detected}/${av.total} | ${icon} ${av.threatLevel} |\n`;
  });
  
  output += '\n';
  return output;
}

function generateGenomicsReport(results) {
  let output = '';
  
  output += '## 🧬 Genomics Report\n\n';
  
  if (!results.uploadResults?.reputations) {
    output += '✅ No violations found\n\n';
    return output;
  }
  
  const reps = results.uploadResults.reputations;
  const similarityFindings = reps.filter(r => {
    const sim = r.reputation?.similarity;
    return sim && (sim.threatLevel === 'high' || sim.threatLevel === 'medium');
  });
  
  if (similarityFindings.length === 0) {
    output += '✅ No violations found\n\n';
    return output;
  }
  
  output += '| File | Similarity Score | Threat Level |\n';
  output += '|------|-----------------|-------------|\n';
  
  similarityFindings.forEach(r => {
    const sim = r.reputation.similarity;
    const icon = sim.threatLevel === 'high' ? '🔴' : '🟠';
    output += `| ${makeLink(r.file, r.sha256)} | ${sim.score} | ${icon} ${sim.threatLevel} |\n`;
  });
  
  output += '\n';
  return output;
}

function generateYaraReport(yaraResults) {
  let output = '';
  
  output += '## 🔎 YARA Scan Report\n\n';
  
  if (!yaraResults?.results || yaraResults.results.length === 0) {
    output += '✅ No violations found\n\n';
    return output;
  }
  
  output += '| File | Rule | Severity |\n';
  output += '|------|------|----------|\n';
  
  yaraResults.results.forEach(r => {
    const fileName = r.file.split('/').slice(-2).join('/');
    const fileLink = r.sha256 ? makeLink(fileName, r.sha256) : fileName;
    
    r.matches.forEach(m => {
      const sev = m.meta?.severity || 'unknown';
      const icon = (sev === 'critical' || sev === 'high') ? '🔴' : sev === 'medium' ? '🟠' : '🟡';
      output += `| ${fileLink} | ${m.rule} | ${icon} ${sev} |\n`;
    });
  });
  
  output += '\n';
  return output;
}

function generateCodeSigningReport(results) {
  let output = '';
  
  output += '## ✍️ Code Signing Report\n\n';
  
  if (!results.uploadResults?.reputations) {
    output += '✅ No violations found\n\n';
    return output;
  }
  
  const reps = results.uploadResults.reputations;
  const unsignedFiles = reps.filter(r => {
    const sig = r.reputation?.signature;
    return sig && sig.threatLevel === 'caution';
  });
  
  if (unsignedFiles.length === 0) {
    output += '✅ No violations found\n\n';
    return output;
  }
  
  output += `| File | Status |\n`;
  output += `|------|--------|\n`;
  
  unsignedFiles.forEach(r => {
    output += `| ${makeLink(r.file, r.sha256)} | ⚠️ Unsigned |\n`;
  });
  
  output += '\n';
  return output;
}

function generateLicenseReport(licenseResults) {
  let output = '';
  
  output += '## 📜 License Compliance Report\n\n';
  
  if (!licenseResults) {
    output += '✅ No violations found\n\n';
    return output;
  }
  
  const allowed = licenseResults.allowed?.length || 0;
  const warning = licenseResults.warning?.length || 0;
  const denied = licenseResults.denied?.length || 0;
  const unknown = licenseResults.unknown?.length || 0;
  
  output += '| Status | Count |\n';
  output += '|--------|-------|\n';
  output += `| ✅ Allowed | ${allowed} |\n`;
  output += `| ⚠️ Warning | ${warning} |\n`;
  output += `| ❌ Denied | ${denied} |\n`;
  output += `| ❓ Unknown | ${unknown} |\n`;
  output += '\n';
  
  if (denied === 0 && warning === 0) {
    output += '✅ No violations found\n\n';
    return output;
  }
  
  if (denied > 0) {
    output += '### ❌ Denied Licenses\n';
    output += '| Package | Version | License |\n';
    output += '|---------|---------|----------|\n';
    licenseResults.denied.forEach(pkg => {
      output += `| ${pkg.name} | ${pkg.version} | ${pkg.license} |\n`;
    });
    output += '\n';
  }
  
  if (warning > 0) {
    output += '### ⚠️ Licenses Requiring Review\n';
    output += '| Package | Version | License |\n';
    output += '|---------|---------|----------|\n';
    if (warning <= 10) {
      licenseResults.warning.forEach(pkg => {
        output += `| ${pkg.name} | ${pkg.version} | ${pkg.license} |\n`;
      });
    } else {
      // Show first 10 and note there are more
      licenseResults.warning.slice(0, 10).forEach(pkg => {
        output += `| ${pkg.name} | ${pkg.version} | ${pkg.license} |\n`;
      });
      output += `| ... | ... | *${warning - 10} more* |\n`;
    }
    output += '\n';
  }
  
  return output;
}

function main() {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  
  if (!summaryPath) {
    console.log('GITHUB_STEP_SUMMARY not set, outputting to console');
  }
  
  let output = '';
  
  // Main header
  output += generateHeader();
  
  // Load results
  let binaryResults = null;
  let yaraResults = null;
  let licenseResults = null;
  
  const binaryResultsPath = 'binary-scan-results.json';
  if (fs.existsSync(binaryResultsPath)) {
    try {
      binaryResults = JSON.parse(fs.readFileSync(binaryResultsPath, 'utf8'));
    } catch (e) {
      console.error('Error parsing binary-scan-results.json:', e.message);
    }
  }
  
  const yaraResultsPath = 'yara-results.json';
  if (fs.existsSync(yaraResultsPath)) {
    try {
      yaraResults = JSON.parse(fs.readFileSync(yaraResultsPath, 'utf8'));
    } catch (e) {
      console.error('Error parsing yara-results.json:', e.message);
    }
  }
  
  const licenseResultsPath = 'license-results.json';
  if (fs.existsSync(licenseResultsPath)) {
    try {
      licenseResults = JSON.parse(fs.readFileSync(licenseResultsPath, 'utf8'));
    } catch (e) {
      console.error('Error parsing license-results.json:', e.message);
    }
  }
  
  // Generate sections in order:
  // 1. Scan Metrics (with upload data)
  if (binaryResults) {
    output += generateScanMetrics(binaryResults);
  }
  
  // 2. Malware Report
  if (binaryResults) {
    output += generateMalwareReport(binaryResults);
  }
  
  // 3. Genomics Report
  if (binaryResults) {
    output += generateGenomicsReport(binaryResults);
  }
  
  // 4. YARA Scan Report
  output += generateYaraReport(yaraResults);
  
  // 5. Code Signing Report
  if (binaryResults) {
    output += generateCodeSigningReport(binaryResults);
  }
  
  // 6. License Compliance Report
  output += generateLicenseReport(licenseResults);
  
  // Output
  if (summaryPath) {
    fs.appendFileSync(summaryPath, output);
    console.log('Summary written to GITHUB_STEP_SUMMARY');
  } else {
    console.log('\n--- Summary Output ---\n');
    console.log(output);
  }
}

main();
