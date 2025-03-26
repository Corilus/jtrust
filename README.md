# jTrust

[![Build Status](https://travis-ci.com/Corilus/jtrust.svg?branch=master)](https://travis-ci.com/Corilus/jtrust)
[![Java CI with Maven](https://github.com/Corilus/jtrust/actions/workflows/maven.yml/badge.svg)](https://github.com/Corilus/jtrust/actions/workflows/maven.yml)

## 📚 Introduction

This project contains the source code tree of the jTrust library, a fork of [e-Contract jtrust](https://github.com/e-Contract/jtrust), maintained and adapted by Corilus. It includes pragmatic PKI validation functionality with fallback support when OCSP servers are unavailable.

- The source code is hosted at: [https://github.com/e-Contract/jtrust](https://github.com/e-Contract/jtrust)
- The Maven project site is hosted at: [https://www.e-contract.be/sites/jtrust/](https://www.e-contract.be/sites/jtrust/)
- Issues can be reported via GitHub: [https://github.com/e-Contract/jtrust/issues](https://github.com/e-Contract/jtrust/issues)
- Also check the eID Applet mailing list for announcements: [https://groups.google.com/forum/#!forum/eid-applet](https://groups.google.com/forum/#!forum/eid-applet)

## 🧩 Structure
- **jtrust-lib**: Core library.
- **jtrust-testpki**: Test certificates and PKI utilities.
- **jtrust-tsl**: Trust Service List processing.
- **jtrust-tests**: Unit and integration tests.

## 🚀 Getting Started
A good entry point for using the jTrust project is the Maven project site:
[https://www.e-contract.be/sites/jtrust/jtrust-lib/](https://www.e-contract.be/sites/jtrust/jtrust-lib/)

## ✅ Requirements
- Oracle Java 1.8.0_232
- Apache Maven 3.6.3+

## 🛠 Build
Build the project with:
```shell
mvn clean install
```

## 🔄 Syncing with Upstream (e-Contract)
### 1. Add Upstream Remote (first time only)
```bash
git remote add upstream https://github.com/e-Contract/jtrust.git
git remote -v
```
### 2. Fetch the latest changes
```bash
git fetch upstream
```
### 3. Merge or Rebase changes
**Option A - Merge:**
```bash
git checkout main
git merge upstream/main
```
**Option B - Rebase (cleaner history):**
```bash
git checkout main
git rebase upstream/main
```
### 4. Resolve conflicts (if any) and push to Azure remote
```bash
git push origin main
```
### 5. Create a Pull Request in Azure DevOps
- Add description: *"Sync with upstream jtrust repository"*
- Add reviewers (Kevin, Thibault, Dennis).
- Wait for the automated build pipeline and artifact release.
### 6. Confirm artifact publication
- Verify in Azure Artifacts that the new `jtrust` version is published.
### 7. Update downstream projects (e.g., `passport`)
- Update the dependency version in `pom.xml`.

## 🚀 Releasing in Azure DevOps
- After merging changes, the CI pipeline will:
    - Automatically build, test, and deploy the new artifact.
    - Publish the artifact to the Azure Artifacts feed.
- Confirm the release via Azure Artifacts.
- Notify integrators for testing.

## 🛡 Risk Reminder
> Always notify integrators to test with different EID cards after changes, as OCSP handling or certificate logic might be impacted.

## ✏ Useful Commands
- Check remotes:
```bash
git remote -v
```
- See commits behind/ahead:
```bash
git fetch upstream
git log HEAD..upstream/main --oneline
```
- Verify current branch:
```bash
git branch
```

## 📜 License
The license conditions can be found in the file: `LICENSE.txt`

## ✉ Contact
- Maintained by Corilus developers.
- Internal contacts: Kevin & Thibault.


## ⚠ Disclaimer
This README has been generated with the assistance of ChatGPT. The content has been reviewed but not all external URLs have been manually tested for correctness.
