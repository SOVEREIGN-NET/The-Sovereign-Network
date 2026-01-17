/**
 * Content Manager - handles file uploads and manifest building
 * Follows zhtp-cli pattern for content storage operations
 */

import { Output } from '../output.js';
import { DomainError, ValidationError } from '../error.js';
import { ZhtpQuicClient } from '../quic/client.js';
import { DeployManifest, FileEntry } from '../types.js';

/**
 * File upload result
 */
export interface FileUploadResult {
  path: string;
  cid: string;
  size: number;
  mimeType: string;
}

/**
 * Manifest build options
 */
export interface ManifestOptions {
  domain: string;
  authorDid: string;
  mode: 'spa' | 'static';
  indexFile?: string; // For SPA mode (default: index.html)
}

/**
 * Content Manager
 */
export class ContentManager {
  constructor(private client: ZhtpQuicClient, private output: Output) {}

  /**
   * Upload a single file to content storage
   */
  async uploadFile(
    path: string,
    data: Uint8Array,
    mimeType: string,
  ): Promise<FileUploadResult> {
    await this.output.info(`Uploading: ${path} (${(data.length / 1024).toFixed(2)} KB)`);

    try {
      // Call content upload endpoint
      // Note: Include path and MIME type in request body or URL if needed by server
      const uploadPayload = {
        path,
        mimeType,
        data: Array.from(data),
      };
      const response = await this.client.request('POST', '/api/v1/web4/content/upload', {
        body: new TextEncoder().encode(JSON.stringify(uploadPayload)),
      });

      if (response.status !== 200 && response.status !== 201) {
        throw new DomainError(`Upload failed: ${response.status}`, {
          path,
          status: response.status,
          data: response.data,
        });
      }

      const responseData = response.data ? JSON.parse(response.data) : null;
      const cid = responseData?.cid || responseData?.hash;

      if (!cid) {
        throw new DomainError('No CID in upload response', { path, response: responseData });
      }

      await this.output.success(`Uploaded: ${path} → ${cid.substring(0, 16)}...`);

      return {
        path,
        cid,
        size: data.length,
        mimeType,
      };
    } catch (error) {
      if (error instanceof DomainError) {
        throw error;
      }
      throw new DomainError(`Upload error: ${error instanceof Error ? error.message : 'unknown'}`, {
        path,
      });
    }
  }

  /**
   * Build deployment manifest from uploaded files
   */
  async buildManifest(
    files: FileUploadResult[],
    options: ManifestOptions,
  ): Promise<DeployManifest> {
    await this.output.info(`Building manifest for ${options.domain} (${options.mode} mode)`);

    const fileEntries: FileEntry[] = files.map((f) => ({
      path: f.path,
      size: f.size,
      mimeType: f.mimeType,
      hash: f.cid,
    }));

    // For SPA mode, ensure index.html is included
    if (options.mode === 'spa') {
      const hasIndex = fileEntries.some((f) => f.path.endsWith('index.html'));
      if (!hasIndex) {
        await this.output.warning('SPA mode: No index.html found');
      }
    }

    // Calculate total size
    const totalSize = BigInt(files.reduce((sum, f) => sum + f.size, 0));

    // Build root hash (combine all CIDs)
    const cidsString = files.map((f) => f.cid).join('|');
    const encoder = new TextEncoder();
    const cidsBytes = encoder.encode(cidsString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', cidsBytes);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const rootHash = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

    const manifest: DeployManifest = {
      version: 1,
      domain: options.domain,
      mode: options.mode,
      files: fileEntries,
      rootHash,
      totalSize,
      deployedAt: Math.floor(Date.now() / 1000),
      authorDid: options.authorDid,
      signature: '', // Will be signed by domain manager
    };

    await this.output.success(`Manifest built: ${fileEntries.length} files, ${(Number(totalSize) / 1024 / 1024).toFixed(2)} MB`);

    return manifest;
  }

  /**
   * Publish manifest to content storage and return CID
   */
  async publishManifest(manifest: DeployManifest): Promise<string> {
    await this.output.info('Publishing manifest to content storage...');

    try {
      const manifestJson = JSON.stringify(manifest);
      const manifestBytes = new TextEncoder().encode(manifestJson);

      const response = await this.client.request('POST', '/api/v1/web4/content/manifest', {
        body: manifestBytes,
      });

      if (response.status !== 200 && response.status !== 201) {
        throw new DomainError(`Manifest publish failed: ${response.status}`, {
          status: response.status,
          data: response.data,
        });
      }

      const responseData = response.data ? JSON.parse(response.data) : null;
      const manifestCid = responseData?.cid || responseData?.hash;

      if (!manifestCid) {
        throw new DomainError('No CID in manifest response', { response: responseData });
      }

      await this.output.success(`Manifest published: ${manifestCid.substring(0, 16)}...`);

      return manifestCid;
    } catch (error) {
      if (error instanceof DomainError) {
        throw error;
      }
      throw new DomainError(`Manifest publish error: ${error instanceof Error ? error.message : 'unknown'}`, {});
    }
  }
}
