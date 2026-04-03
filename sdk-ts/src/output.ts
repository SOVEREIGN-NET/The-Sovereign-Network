/**
 * Output abstraction for testability
 * Allows dependency injection of console, mock, or file-based output
 */

export interface Output {
  print(message: string): Promise<void>;
  printJson(data: any): Promise<void>;
  error(message: string): Promise<void>;
  success(message: string): Promise<void>;
  warning(message: string): Promise<void>;
  info(message: string): Promise<void>;
  header(title: string): Promise<void>;
  debug(message: string): Promise<void>;
}

/**
 * Console output implementation
 */
export class ConsoleOutput implements Output {
  async print(message: string): Promise<void> {
    console.log(message);
  }

  async printJson(data: any): Promise<void> {
    console.log(JSON.stringify(data, (_, value) => {
      // Handle bigint serialization
      return typeof value === 'bigint' ? value.toString() : value;
    }, 2));
  }

  async error(message: string): Promise<void> {
    console.error(`❌ ${message}`);
  }

  async success(message: string): Promise<void> {
    console.log(`✅ ${message}`);
  }

  async warning(message: string): Promise<void> {
    console.warn(`⚠️  ${message}`);
  }

  async info(message: string): Promise<void> {
    console.log(`ℹ️  ${message}`);
  }

  async header(title: string): Promise<void> {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`  ${title}`);
    console.log(`${'='.repeat(60)}\n`);
  }

  async debug(message: string): Promise<void> {
    if (process.env.DEBUG) {
      console.debug(`🔍 ${message}`);
    }
  }
}

/**
 * Silent output for production use
 */
export class SilentOutput implements Output {
  async print(): Promise<void> {}
  async printJson(): Promise<void> {}
  async error(): Promise<void> {}
  async success(): Promise<void> {}
  async warning(): Promise<void> {}
  async info(): Promise<void> {}
  async header(): Promise<void> {}
  async debug(): Promise<void> {}
}

/**
 * Mock output for testing
 */
export class MockOutput implements Output {
  messages: string[] = [];
  errors: string[] = [];
  successes: string[] = [];
  warnings: string[] = [];
  infos: string[] = [];

  async print(message: string): Promise<void> {
    this.messages.push(message);
  }

  async printJson(data: any): Promise<void> {
    this.messages.push(JSON.stringify(data, (_, value) => {
      // Handle bigint serialization
      return typeof value === 'bigint' ? value.toString() : value;
    }));
  }

  async error(message: string): Promise<void> {
    this.errors.push(message);
  }

  async success(message: string): Promise<void> {
    this.successes.push(message);
  }

  async warning(message: string): Promise<void> {
    this.warnings.push(message);
  }

  async info(message: string): Promise<void> {
    this.infos.push(message);
  }

  async header(): Promise<void> {}

  async debug(): Promise<void> {}

  /**
   * Clear all recorded output
   */
  clear(): void {
    this.messages = [];
    this.errors = [];
    this.successes = [];
    this.warnings = [];
    this.infos = [];
  }

  /**
   * Get all recorded messages
   */
  getAll(): string[] {
    return [
      ...this.errors.map(e => `ERROR: ${e}`),
      ...this.warnings.map(w => `WARN: ${w}`),
      ...this.infos.map(i => `INFO: ${i}`),
      ...this.successes.map(s => `SUCCESS: ${s}`),
      ...this.messages,
    ];
  }
}
