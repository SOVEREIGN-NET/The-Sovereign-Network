/**
 * DeployManager - Handles dApp and website deployments
 */

import { Transport } from '../transport/types.js';
import { IdentityManager } from '../crypto/identity.js';
import {
  DeployResult,
  UpdateResult,
  Deployment,
  Manifest,
  FileEntry,
  ClientOptions,
  ProgressCallback,
} from '../types/domain.js';
import { validateDomain } from '../crypto/utils.js';
import { ContentManager } from './content.js';
import { DomainManager } from './domain.js';

export class DeployManager {
  private contentManager: ContentManager;
  private domainManager: DomainManager;

  constructor(
    private transport: Transport,
    private identity: IdentityManager,
    private options: Required<ClientOptions>
  ) {
    this.contentManager = new ContentManager(transport, identity, options);
    this.domainManager = new DomainManager(transport, identity, options);
  }

  /**
   * Deploy a static website or SPA to a domain
   */
  async deploySite(
    domain: string,
    buildDir: string,
    _mode: 'spa' | 'static' = 'static',
    onProgress?: ProgressCallback,
    metadata?: Record<string, string>
  ): Promise<DeployResult> {
    // Validate domain
    if (!validateDomain(domain)) {
      throw new Error(`Invalid domain name: ${domain}`);
    }

    // TODO: Implement actual file system scanning
    // For now, we'll use a placeholder implementation
    console.log(`Preparing to deploy from ${buildDir} to ${domain} in ${_mode} mode`);

    // Scan build directory for files (placeholder)
    const files = await this.scanBuildDirectory(buildDir);

    if (files.length === 0) {
      throw new Error(`No files found in build directory: ${buildDir}`);
    }

    // Upload files
    const uploadedFiles: Record<string, FileEntry> = {};
    let totalSize = 0;

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const data = file.data;
      totalSize += data.length;

      if (onProgress) {
        onProgress({
          loaded: totalSize,
          total: files.reduce((sum, f) => sum + f.data.length, 0),
          percentage: ((i + 1) / files.length) * 100,
          status: `uploading ${file.name}`,
        });
      }

      const cid = await this.contentManager.uploadBlob(data, file.mimeType);
      uploadedFiles[file.name] = {
        cid,
        size: data.length,
        mimeType: file.mimeType,
        path: file.path,
      };
    }

    // Create manifest
    const manifest: Manifest = {
      version: 1,
      created: Date.now(),
      updated: Date.now(),
      files: uploadedFiles,
      root: this.getIndexFile(uploadedFiles),
      metadata,
    };

    // Upload manifest
    const manifestCid = await this.contentManager.uploadManifest(manifest);

    // Register domain or update content
    try {
      await this.domainManager.getInfo(domain);
      // Domain exists, update it
      await this.updateDomainContent(domain, manifestCid);
    } catch {
      // Domain doesn't exist, register it
      await this.domainManager.register(domain, metadata ? { contentCid: manifestCid, metadata } : { contentCid: manifestCid });
    }

    if (onProgress) {
      onProgress({
        loaded: totalSize,
        total: totalSize,
        percentage: 100,
        status: 'complete',
      });
    }

    return {
      domain,
      manifestCid,
      version: 1,
      filesDeployed: Object.keys(uploadedFiles).length,
      totalSize,
      deployedAt: Date.now(),
      url: `zhtp://${domain}`,
    };
  }

  /**
   * Update an existing deployment
   */
  async update(
    domain: string,
    buildDir: string,
    onProgress?: ProgressCallback,
    metadata?: Record<string, string>
  ): Promise<UpdateResult> {
    // Validate domain
    if (!validateDomain(domain)) {
      throw new Error(`Invalid domain name: ${domain}`);
    }

    // Get current domain info
    const domainInfo = await this.domainManager.getInfo(domain);

    // Scan build directory for files
    const files = await this.scanBuildDirectory(buildDir);

    if (files.length === 0) {
      throw new Error(`No files found in build directory: ${buildDir}`);
    }

    // Upload files
    const uploadedFiles: Record<string, FileEntry> = {};
    let totalSize = 0;

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const data = file.data;
      totalSize += data.length;

      if (onProgress) {
        onProgress({
          loaded: totalSize,
          total: files.reduce((sum, f) => sum + f.data.length, 0),
          percentage: ((i + 1) / files.length) * 100,
          status: `uploading ${file.name}`,
        });
      }

      const cid = await this.contentManager.uploadBlob(data, file.mimeType);
      uploadedFiles[file.name] = {
        cid,
        size: data.length,
        mimeType: file.mimeType,
        path: file.path,
      };
    }

    // Create new manifest with incremented version
    const currentManifest = await this.contentManager.fetchManifest(domainInfo.contentCid);
    const newVersion = currentManifest.version + 1;

    const manifest: Manifest = {
      version: newVersion,
      created: currentManifest.created,
      updated: Date.now(),
      files: uploadedFiles,
      root: this.getIndexFile(uploadedFiles),
      metadata,
    };

    // Upload new manifest
    const manifestCid = await this.contentManager.uploadManifest(manifest);

    // Update domain content
    await this.updateDomainContent(domain, manifestCid);

    if (onProgress) {
      onProgress({
        loaded: totalSize,
        total: totalSize,
        percentage: 100,
        status: 'complete',
      });
    }

    return {
      domain,
      manifestCid,
      version: newVersion,
      filesDeployed: Object.keys(uploadedFiles).length,
      totalSize,
      updatedAt: Date.now(),
    };
  }

  /**
   * Get deployment history
   */
  async getDeployments(domain: string): Promise<Deployment[]> {
    if (!validateDomain(domain)) {
      throw new Error(`Invalid domain name: ${domain}`);
    }

    const response = await this.transport.get<Deployment[]>(
      `/api/v1/web4/deployments?domain=${encodeURIComponent(domain)}`
    );

    return response.body;
  }

  /**
   * Rollback to a previous deployment
   */
  async rollback(domain: string, version: number): Promise<boolean> {
    if (!validateDomain(domain)) {
      throw new Error(`Invalid domain name: ${domain}`);
    }

    await this.transport.post(`/api/v1/web4/deployments/rollback`, {
      domain,
      version,
      publicKey: this.identity.getPublicKey(),
      signature: '', // TODO: Add actual signature
    });

    return true;
  }

  /**
   * Delete a deployment
   */
  async delete(domain: string): Promise<boolean> {
    if (!validateDomain(domain)) {
      throw new Error(`Invalid domain name: ${domain}`);
    }

    await this.transport.post(`/api/v1/web4/deployments/delete`, {
      domain,
      publicKey: this.identity.getPublicKey(),
      signature: '', // TODO: Add actual signature
    });

    return true;
  }

  /**
   * Scan build directory for files (placeholder)
   */
  private async scanBuildDirectory(
    buildDir: string
  ): Promise<Array<{ name: string; path: string; data: Uint8Array; mimeType: string }>> {
    // TODO: Implement actual file system scanning
    // This requires Node.js fs module which we'll use in production
    console.log(`Scanning build directory: ${buildDir}`);

    return [
      {
        name: 'index.html',
        path: 'index.html',
        data: new Uint8Array(Buffer.from('<html><body>Hello ZHTP</body></html>')),
        mimeType: 'text/html',
      },
    ];
  }

  /**
   * Get the root/index file for deployments
   */
  private getIndexFile(files: Record<string, FileEntry>): string {
    const indexFile = files['index.html'];
    if (!indexFile) {
      throw new Error('index.html not found in deployment files');
    }

    return indexFile.cid;
  }

  /**
   * Update domain content to point to new manifest
   */
  private async updateDomainContent(domain: string, manifestCid: string): Promise<void> {
    await this.transport.post(`/api/v1/web4/domains/update-content`, {
      domain,
      contentCid: manifestCid,
      publicKey: this.identity.getPublicKey(),
      signature: '', // TODO: Add actual signature
    });
  }
}
