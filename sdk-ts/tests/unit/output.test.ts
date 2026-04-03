import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ConsoleOutput, SilentOutput, MockOutput } from '../../src/output.js';

describe('Output Implementations', () => {
  describe('ConsoleOutput', () => {
    let consoleLogSpy: any;
    let consoleErrorSpy: any;
    let consoleWarnSpy: any;

    beforeEach(() => {
      consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    });

    it('prints plain messages', async () => {
      const output = new ConsoleOutput();
      await output.print('Hello, world!');
      expect(consoleLogSpy).toHaveBeenCalledWith('Hello, world!');
    });

    it('prints JSON with bigint support', async () => {
      const output = new ConsoleOutput();
      const data = {
        amount: 1000n,
        name: 'test',
      };
      await output.printJson(data);
      // Should not throw on bigint
      expect(consoleLogSpy).toHaveBeenCalled();
      const jsonString = consoleLogSpy.mock.calls[0][0];
      expect(jsonString).toContain('"amount": "1000"');
    });

    it('prints error messages with emoji', async () => {
      const output = new ConsoleOutput();
      await output.error('Something failed');
      expect(consoleErrorSpy).toHaveBeenCalledWith('❌ Something failed');
    });

    it('prints success messages with emoji', async () => {
      const output = new ConsoleOutput();
      await output.success('Operation completed');
      expect(consoleLogSpy).toHaveBeenCalledWith('✅ Operation completed');
    });

    it('prints warning messages with emoji', async () => {
      const output = new ConsoleOutput();
      await output.warning('Be careful');
      expect(consoleWarnSpy).toHaveBeenCalledWith('⚠️  Be careful');
    });

    it('prints info messages with emoji', async () => {
      const output = new ConsoleOutput();
      await output.info('FYI');
      expect(consoleLogSpy).toHaveBeenCalledWith('ℹ️  FYI');
    });

    it('prints header with separators', async () => {
      const output = new ConsoleOutput();
      await output.header('My Section');
      const calls = consoleLogSpy.mock.calls;
      expect(calls.length).toBe(3);
      expect(calls[0][0]).toContain('=');
      expect(calls[1][0]).toContain('My Section');
      expect(calls[2][0]).toContain('=');
    });

    it('respects DEBUG env var for debug messages', async () => {
      const output = new ConsoleOutput();

      // Mock debugger
      vi.spyOn(console, 'debug', 'get').mockReturnValue(vi.fn());
      const debugSpy = vi.spyOn(console, 'debug').mockImplementation(() => {});

      // Without DEBUG env var
      await output.debug('Debug message');
      expect(debugSpy).not.toHaveBeenCalled();

      // With DEBUG env var
      const oldDebug = process.env.DEBUG;
      process.env.DEBUG = '1';
      await output.debug('Debug message');
      expect(debugSpy).toHaveBeenCalledWith('🔍 Debug message');
      process.env.DEBUG = oldDebug;
    });
  });

  describe('SilentOutput', () => {
    it('does nothing for any output', async () => {
      const output = new SilentOutput();
      const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      await output.print('message');
      await output.success('success');
      await output.error('error');
      await output.warning('warning');
      await output.info('info');
      await output.header('header');
      await output.debug('debug');
      await output.printJson({ data: 'json' });

      expect(consoleLogSpy).not.toHaveBeenCalled();
    });
  });

  describe('MockOutput', () => {
    it('records printed messages', async () => {
      const output = new MockOutput();
      await output.print('message 1');
      await output.print('message 2');

      expect(output.messages).toEqual(['message 1', 'message 2']);
    });

    it('records errors separately', async () => {
      const output = new MockOutput();
      await output.error('error 1');
      await output.error('error 2');

      expect(output.errors).toEqual(['error 1', 'error 2']);
    });

    it('records successes separately', async () => {
      const output = new MockOutput();
      await output.success('success 1');
      await output.success('success 2');

      expect(output.successes).toEqual(['success 1', 'success 2']);
    });

    it('records warnings separately', async () => {
      const output = new MockOutput();
      await output.warning('warning 1');
      await output.warning('warning 2');

      expect(output.warnings).toEqual(['warning 1', 'warning 2']);
    });

    it('records infos separately', async () => {
      const output = new MockOutput();
      await output.info('info 1');
      await output.info('info 2');

      expect(output.infos).toEqual(['info 1', 'info 2']);
    });

    it('records JSON as stringified', async () => {
      const output = new MockOutput();
      const data = { key: 'value', amount: 1000n };
      await output.printJson(data);

      expect(output.messages.length).toBe(1);
      const json = JSON.parse(output.messages[0]);
      expect(json.key).toBe('value');
      expect(json.amount).toBe('1000'); // bigint converted to string
    });

    it('provides getAll() method combining all output', async () => {
      const output = new MockOutput();
      await output.error('err');
      await output.warning('warn');
      await output.info('info');
      await output.success('suc');
      await output.print('msg');

      const all = output.getAll();
      expect(all).toContain('ERROR: err');
      expect(all).toContain('WARN: warn');
      expect(all).toContain('INFO: info');
      expect(all).toContain('SUCCESS: suc');
      expect(all).toContain('msg');
    });

    it('clears all recorded output', async () => {
      const output = new MockOutput();
      await output.print('message');
      await output.error('error');
      await output.success('success');

      output.clear();

      expect(output.messages).toEqual([]);
      expect(output.errors).toEqual([]);
      expect(output.successes).toEqual([]);
      expect(output.warnings).toEqual([]);
      expect(output.infos).toEqual([]);
    });

    it('ignores header and debug', async () => {
      const output = new MockOutput();
      await output.header('Header');
      await output.debug('Debug');

      // Should not record these
      expect(output.messages.length).toBe(0);
      expect(output.getAll().length).toBe(0);
    });

    it('handles mixed output types correctly', async () => {
      const output = new MockOutput();
      await output.print('msg1');
      await output.error('err1');
      await output.print('msg2');
      await output.success('suc1');
      await output.warning('warn1');

      const all = output.getAll();
      // getAll() returns: errors, warnings, infos, successes, then messages
      expect(all[0]).toContain('ERROR: err1');
      expect(all[1]).toContain('WARN: warn1');
      expect(all[2]).toContain('SUCCESS: suc1');
      expect(all[3]).toBe('msg1');
      expect(all[4]).toBe('msg2');
    });
  });
});
