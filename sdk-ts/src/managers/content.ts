/**
 * ContentManager - Handles content/blob uploads and manifest operations
 */

import { Transport } from '../transport/types.js';
import { IdentityManager } from '../crypto/identity.js';
import { Manifest, ClientOptions, ProgressCallback } from '../types/domain.js';
import { ManifestContent } from '../types/requests.js';
import { BlobUploadResponse, ManifestUploadResponse, ManifestFetchResponse } from '../types/responses.js';
import { calculateContentHash } from '../crypto/utils.js';

const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB chunks

export class ContentManager {
  constructor(
    private transport: Transport,
    private identity: IdentityManager,
    _options: Required<ClientOptions>
  ) {}

  /**
   * Upload a blob (file) to content storage
   */
  async uploadBlob(
    data: Uint8Array,
    contentType: string,
    onProgress?: ProgressCallback
  ): Promise<string> {
    if (data.length > 256 * 1024 * 1024) {
      throw new Error('File size exceeds 256MB limit');
    }

    // For large files, use chunked upload
    if (data.length > CHUNK_SIZE) {
      return this.uploadBlobChunked(data, contentType, onProgress);
    }

    // Small files: direct upload
    const response = await this.transport.post<BlobUploadResponse>(
      '/api/v1/web4/content/upload',
      {
        data: Array.from(data),
        contentType,
      },
      {
        headers: {
          'Content-Type': contentType,
        },
      }
    );

    if (onProgress) {
      onProgress({
        loaded: data.length,
        total: data.length,
        percentage: 100,
        status: 'complete',
      });
    }

    return response.body.cid;
  }

  /**
   * Upload a blob in chunks (for files > 5MB)
   */
  private async uploadBlobChunked(
    data: Uint8Array,
    contentType: string,
    onProgress?: ProgressCallback
  ): Promise<string> {
    // Initialize chunked upload session
    const initResponse = await this.transport.post<{ uploadId: string; expiresAt: number }>(
      '/api/v1/web4/content/upload/init',
      {
        contentType,
        totalSize: data.length,
        filename: `blob-${Date.now()}`,
      }
    );

    const uploadId = initResponse.body.uploadId;
    const totalChunks = Math.ceil(data.length / CHUNK_SIZE);

    // Upload chunks
    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min((i + 1) * CHUNK_SIZE, data.length);
      const chunk = data.slice(start, end);

      await this.transport.post(
        `/api/v1/web4/content/upload/chunk`,
        {
          uploadId,
          chunkIndex: i,
          chunk: Array.from(chunk),
          totalChunks,
        }
      );

      if (onProgress) {
        const percentage = ((i + 1) / totalChunks) * 100;
        onProgress({
          loaded: end,
          total: data.length,
          percentage,
          status: `uploading (${i + 1}/${totalChunks})`,
        });
      }
    }

    // Finalize upload
    const contentHash = calculateContentHash(data);
    const finalizeResponse = await this.transport.post<{ cid: string }>(
      '/api/v1/web4/content/upload/finalize',
      {
        uploadId,
        contentHash,
      }
    );

    return finalizeResponse.body.cid;
  }

  /**
   * Fetch a blob by CID
   */
  async fetchBlob(cid: string): Promise<Uint8Array> {
    const response = await this.transport.get<Uint8Array>(
      `/api/v1/web4/content/blob?cid=${encodeURIComponent(cid)}`
    );

    return response.raw;
  }

  /**
   * Upload a manifest (JSON describing deployed content)
   */
  async uploadManifest(manifest: Manifest): Promise<string> {
    const manifestData: ManifestContent = {
      version: manifest.version,
      created: manifest.created,
      updated: manifest.updated,
      files: manifest.files,
      root: manifest.root,
      metadata: manifest.metadata,
    };

    const response = await this.transport.post<ManifestUploadResponse>(
      '/api/v1/web4/content/manifest/upload',
      {
        manifest: manifestData,
        signature: '', // TODO: Add actual signature
        publicKey: this.identity.getPublicKey(),
      }
    );

    return response.body.cid;
  }

  /**
   * Fetch a manifest by CID
   */
  async fetchManifest(cid: string): Promise<Manifest> {
    const response = await this.transport.get<ManifestFetchResponse>(
      `/api/v1/web4/content/manifest?cid=${encodeURIComponent(cid)}`
    );

    return {
      version: response.body.version,
      created: response.body.created,
      updated: response.body.updated,
      files: response.body.files,
      root: response.body.root,
      metadata: response.body.metadata,
    };
  }

  /**
   * Check if content exists
   */
  async contentExists(cid: string): Promise<boolean> {
    try {
      const response = await this.transport.get<{ exists: boolean }>(
        `/api/v1/web4/content/check?cid=${encodeURIComponent(cid)}`
      );
      return response.body.exists;
    } catch {
      return false;
    }
  }

  /**
   * Get content metadata
   */
  async getContentInfo(cid: string): Promise<{
    cid: string;
    size: number;
    contentType: string;
    uploadedAt: number;
  }> {
    const response = await this.transport.get(
      `/api/v1/web4/content/info?cid=${encodeURIComponent(cid)}`
    );

    return response.body as {
      cid: string;
      size: number;
      contentType: string;
      uploadedAt: number;
    };
  }

  /**
   * Publish content (make it public)
   */
  async publishContent(cid: string, metadata?: Record<string, string>): Promise<boolean> {
    await this.transport.post(`/api/v1/web4/content/publish`, {
      cid,
      publicKey: this.identity.getPublicKey(),
      signature: '', // TODO: Add actual signature
      metadata,
    });

    return true;
  }

  /**
   * Delete content
   */
  async deleteContent(cid: string): Promise<boolean> {
    await this.transport.delete(`/api/v1/web4/content/${encodeURIComponent(cid)}`);
    return true;
  }
}
