import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadBucketCommand,
  CreateBucketCommand
} from "@aws-sdk/client-s3";
import {
  containsPotentialPlaintextSecret,
  validateSafePathWithinRoot
} from "@indicative/security";

export interface StoredArtifact {
  storageKey: string;
  contentType: string;
  sizeBytes: number;
  sha256: string;
}

export interface ArtifactStorageAdapter {
  putObject(
    key: string,
    body: Buffer | string,
    contentType: string
  ): Promise<StoredArtifact>;
  getObject(key: string): Promise<Buffer>;
  deleteObject(key: string): Promise<void>;
  healthCheck(): Promise<{ ok: boolean; driver: string; message?: string }>;
}

function assertSafeArtifactContent(body: Buffer | string): Buffer {
  const buf = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  const textSample = buf.toString("utf8");
  if (containsPotentialPlaintextSecret(textSample)) {
    throw new Error(
      "SECURITY_VIOLATION: Refusing to persist artifact containing potential plaintext secret."
    );
  }
  return buf;
}

export class LocalArtifactStorage implements ArtifactStorageAdapter {
  private readonly baseDir: string;

  constructor(baseDir: string) {
    this.baseDir = path.resolve(baseDir);
  }

  async putObject(
    key: string,
    body: Buffer | string,
    contentType: string
  ): Promise<StoredArtifact> {
    const buf = assertSafeArtifactContent(body);
    const fullPath = validateSafePathWithinRoot(this.baseDir, key);
    await fs.mkdir(path.dirname(fullPath), { recursive: true });
    await fs.writeFile(fullPath, buf);
    const sha256 = crypto.createHash("sha256").update(buf).digest("hex");
    return {
      storageKey: key,
      contentType,
      sizeBytes: buf.byteLength,
      sha256
    };
  }

  async getObject(key: string): Promise<Buffer> {
    const fullPath = validateSafePathWithinRoot(this.baseDir, key);
    return fs.readFile(fullPath);
  }

  async deleteObject(key: string): Promise<void> {
    const fullPath = validateSafePathWithinRoot(this.baseDir, key);
    await fs.rm(fullPath, { force: true });
  }

  async healthCheck(): Promise<{ ok: boolean; driver: string; message?: string }> {
    try {
      await fs.mkdir(this.baseDir, { recursive: true });
      return { ok: true, driver: "local" };
    } catch (err) {
      return { ok: false, driver: "local", message: (err as Error).message };
    }
  }
}

export interface S3ArtifactStorageOptions {
  endpoint: string;
  region: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  forcePathStyle: boolean;
}

export class S3ArtifactStorage implements ArtifactStorageAdapter {
  private readonly client: S3Client;
  private readonly bucket: string;
  private bucketEnsured = false;

  constructor(options: S3ArtifactStorageOptions) {
    this.bucket = options.bucket;
    this.client = new S3Client({
      endpoint: options.endpoint,
      region: options.region,
      forcePathStyle: options.forcePathStyle,
      credentials: {
        accessKeyId: options.accessKeyId,
        secretAccessKey: options.secretAccessKey
      }
    });
  }

  private async ensureBucket(): Promise<void> {
    if (this.bucketEnsured) return;
    try {
      await this.client.send(new HeadBucketCommand({ Bucket: this.bucket }));
    } catch {
      await this.client.send(new CreateBucketCommand({ Bucket: this.bucket }));
    }
    this.bucketEnsured = true;
  }

  async putObject(
    key: string,
    body: Buffer | string,
    contentType: string
  ): Promise<StoredArtifact> {
    const buf = assertSafeArtifactContent(body);
    await this.ensureBucket();
    const sha256 = crypto.createHash("sha256").update(buf).digest("hex");
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: buf,
        ContentType: contentType
      })
    );
    return {
      storageKey: key,
      contentType,
      sizeBytes: buf.byteLength,
      sha256
    };
  }

  async getObject(key: string): Promise<Buffer> {
    const res = await this.client.send(
      new GetObjectCommand({ Bucket: this.bucket, Key: key })
    );
    const bytes = await res.Body?.transformToByteArray();
    if (!bytes) {
      throw new Error(`Artifact not found: ${key}`);
    }
    return Buffer.from(bytes);
  }

  async deleteObject(key: string): Promise<void> {
    await this.client.send(
      new DeleteObjectCommand({ Bucket: this.bucket, Key: key })
    );
  }

  async healthCheck(): Promise<{ ok: boolean; driver: string; message?: string }> {
    try {
      await this.ensureBucket();
      return { ok: true, driver: "s3" };
    } catch (err) {
      return { ok: false, driver: "s3", message: (err as Error).message };
    }
  }
}
