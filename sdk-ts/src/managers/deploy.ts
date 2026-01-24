/**
 * Deploy Manager - orchestrates site deployment workflow
 * Handles: directory reading → file uploads → manifest building → domain update
 */

import { Output } from '../output.js';
import { DomainError, ValidationError } from '../error.js';
import { ZhtpQuicClient } from '../quic/client.js';
import { DomainManager } from './domain.js';
import { ContentManager, ManifestOptions } from './content.js';
import { DeployManifest } from '../types.js';
import { validateDomain } from '../validation.js';

/**
 * Deployment options
 */
export interface DeployOptions {
  domain: string;
  buildDir: string;
  mode: 'spa' | 'static';
  indexFile?: string; // For SPA mode
  exclude?: string[]; // Patterns to exclude
}

/**
 * Deployment result
 */
export interface DeployResult {
  domain: string;
  manifestCid: string;
  fileCount: number;
  totalSize: number;
  deployedAt: number;
  url: string;
}

/**
 * Deploy Manager
 */
export class DeployManager {
  private contentManager: ContentManager;

  constructor(
    private domainManager: DomainManager,
    private client: ZhtpQuicClient,
    private output: Output,
  ) {
    this.contentManager = new ContentManager(client, output);
  }

  /**
   * Deploy a site from a build directory
   */
  async deploySite(options: DeployOptions): Promise<DeployResult> {
    // Validate domain
    const validation = validateDomain(options.domain);
    if (!validation.valid) {
      throw new ValidationError('Invalid domain', validation.errors);
    }

    await this.output.info(`\n🚀 Starting deployment for ${options.domain}`);
    await this.output.info(`   Mode: ${options.mode}`);
    await this.output.info(`   Build dir: ${options.buildDir}`);

    try {
      // Step 1: Read files from build directory
      await this.output.info('\n📂 Reading build directory...');
      const files = await this.readBuildDirectory(options.buildDir, options.exclude || []);

      if (files.length === 0) {
        throw new DomainError('No files found in build directory', { dir: options.buildDir });
      }

      await this.output.success(`Found ${files.length} files`);

      // Step 2: Upload files
      await this.output.info(`\n📤 Uploading ${files.length} files...`);
      const uploadedFiles = await Promise.all(
        files.map((f) =>
          this.contentManager.uploadFile(
            f.path,
            f.data,
            f.mimeType || this.getMimeType(f.path),
          ),
        ),
      );

      // Step 3: Build manifest
      await this.output.info('\n📋 Building deployment manifest...');
      const manifest = await this.contentManager.buildManifest(uploadedFiles, {
        domain: options.domain,
        authorDid: 'did:zhtp:current-user', // Would be actual user DID
        mode: options.mode,
        indexFile: options.indexFile,
      });

      // Step 4: Publish manifest
      await this.output.info('\n🔤 Publishing manifest...');
      const manifestCid = await this.contentManager.publishManifest(manifest);

      // Step 5: Register or update domain
      await this.output.info('\n🔗 Registering domain with manifest...');
      await this.domainManager.register(options.domain, {
        contentCid: manifestCid,
        years: 1,
        metadata: {
          deploymentMode: options.mode,
          deploymentVersion: '1',
        },
      });

      const totalSize = uploadedFiles.reduce((sum, f) => sum + f.size, 0);
      const result: DeployResult = {
        domain: options.domain,
        manifestCid,
        fileCount: uploadedFiles.length,
        totalSize,
        deployedAt: Math.floor(Date.now() / 1000),
        url: `zhtp://${options.domain}`,
      };

      await this.output.success(`\n✅ Deployment complete!`);
      await this.output.info(`   Domain: ${result.url}`);
      await this.output.info(`   Manifest: ${manifestCid.substring(0, 16)}...`);
      await this.output.info(`   Files: ${result.fileCount}`);
      await this.output.info(`   Size: ${(result.totalSize / 1024 / 1024).toFixed(2)} MB\n`);

      return result;
    } catch (error) {
      if (error instanceof ValidationError || error instanceof DomainError) {
        throw error;
      }
      throw new DomainError(`Deployment error: ${error instanceof Error ? error.message : 'unknown'}`, {
        domain: options.domain,
      });
    }
  }

  /**
   * Read all files from build directory recursively
   * NOTE: Node.js-only implementation
   */
  private async readBuildDirectory(
    dir: string,
    exclude: string[],
  ): Promise<Array<{ path: string; data: Uint8Array; mimeType?: string }>> {
    const files: Array<{ path: string; data: Uint8Array; mimeType?: string }> = [];

    try {
      const fs = require('fs');
      const path = require('path');

      const readDir = (currentDir: string, basePath: string = '') => {
        const entries = fs.readdirSync(currentDir, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = path.join(currentDir, entry.name);
          const relativePath = path.join(basePath, entry.name).replace(/\\/g, '/');

          // Skip excluded patterns
          if (exclude.some((pattern) => relativePath.includes(pattern))) {
            continue;
          }

          if (entry.isDirectory()) {
            readDir(fullPath, relativePath);
          } else {
            const data = fs.readFileSync(fullPath);
            files.push({
              path: relativePath,
              data: new Uint8Array(data),
              mimeType: this.getMimeType(relativePath),
            });
          }
        }
      };

      readDir(dir);
    } catch (error) {
      throw new DomainError(`Cannot read directory: ${error instanceof Error ? error.message : 'unknown'}`, {
        dir,
      });
    }

    return files;
  }

  /**
   * Get MIME type for file path
   */
  private getMimeType(filePath: string): string {
    const ext = filePath.split('.').pop()?.toLowerCase() || '';

    const mimeTypes: Record<string, string> = {
      html: 'text/html',
      htm: 'text/html',
      css: 'text/css',
      js: 'application/javascript',
      mjs: 'application/javascript',
      json: 'application/json',
      png: 'image/png',
      jpg: 'image/jpeg',
      jpeg: 'image/jpeg',
      gif: 'image/gif',
      svg: 'image/svg+xml',
      webp: 'image/webp',
      ico: 'image/x-icon',
      woff: 'font/woff',
      woff2: 'font/woff2',
      ttf: 'font/ttf',
      otf: 'font/otf',
      mp3: 'audio/mpeg',
      mp4: 'video/mp4',
      pdf: 'application/pdf',
      zip: 'application/zip',
      txt: 'text/plain',
    };

    return mimeTypes[ext] || 'application/octet-stream';
  }
}
