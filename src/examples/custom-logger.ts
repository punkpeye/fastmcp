/**
 * Example FastMCP server demonstrating custom logger implementations.
 *
 * Features demonstrated:
 * - Simple custom logger implementation
 * - File-based logging example
 * - Winston logger adapter
 * - Pino logger adapter
 *
 */

import { z } from "zod";

import { FastMCP, Logger } from "../FastMCP.js";

// Example 1: Simple Custom Logger Implementation
class SimpleCustomLogger implements Logger {
  debug(...args: unknown[]): void {
    console.log("[CUSTOM DEBUG]", new Date().toISOString(), ...args);
  }

  error(...args: unknown[]): void {
    console.error("[CUSTOM ERROR]", new Date().toISOString(), ...args);
  }

  info(...args: unknown[]): void {
    console.info("[CUSTOM INFO]", new Date().toISOString(), ...args);
  }

  log(...args: unknown[]): void {
    console.log("[CUSTOM LOG]", new Date().toISOString(), ...args);
  }

  warn(...args: unknown[]): void {
    console.warn("[CUSTOM WARN]", new Date().toISOString(), ...args);
  }
}

// Example 2: File-based Logger
// class FileLogger implements Logger {
//   debug(...args: unknown[]): void {
//     this.logToFile('DEBUG', ...args);
//   }

//   error(...args: unknown[]): void {
//     this.logToFile('ERROR', ...args);
//   }

//   info(...args: unknown[]): void {
//     this.logToFile('INFO', ...args);
//   }

//   log(...args: unknown[]): void {
//     this.logToFile('LOG', ...args);
//   }

//   warn(...args: unknown[]): void {
//     this.logToFile('WARN', ...args);
//   }

//   private logToFile(level: string, ...args: unknown[]): void {
//     const timestamp = new Date().toISOString();
//     const message = `[${timestamp}] [${level}] ${args.map(arg =>
//       typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
//     ).join(' ')}\n`;

//     // In a real implementation, you might use fs.appendFile or a logging library
//     console.log(message.trim());
//   }
// }

// Example 3: Winston Logger Adapter
// To use this example, install winston: npm install winston
// import winston from 'winston';

// class WinstonLoggerAdapter implements Logger {
//   private winston: winston.Logger;

//   constructor() {
//     this.winston = winston.createLogger({
//       level: 'debug',
//       format: winston.format.combine(
//         winston.format.timestamp(),
//         winston.format.errors({ stack: true }),
//         winston.format.json()
//       ),
//       transports: [
//         new winston.transports.Console({
//           format: winston.format.combine(
//             winston.format.colorize(),
//             winston.format.simple()
//           )
//         }),
//         new winston.transports.File({ filename: 'fastmcp.log' })
//       ]
//     });
//   }

//   debug(...args: unknown[]): void {
//     this.winston.debug(this.formatArgs(args));
//   }

//   error(...args: unknown[]): void {
//     this.winston.error(this.formatArgs(args));
//   }

//   info(...args: unknown[]): void {
//     this.winston.info(this.formatArgs(args));
//   }

//   log(...args: unknown[]): void {
//     this.winston.info(this.formatArgs(args));
//   }

//   warn(...args: unknown[]): void {
//     this.winston.warn(this.formatArgs(args));
//   }

//   private formatArgs(args: unknown[]): string {
//     return args.map(arg =>
//       typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
//     ).join(' ');
//   }
// }

// Example 4: Pino Logger Adapter
// To use this example, install pino: npm install pino
// import pino from 'pino';
//
// class PinoLoggerAdapter implements Logger {
//   private pino: pino.Logger;
//
//   constructor() {
//     this.pino = pino({
//       level: 'debug',
//       transport: {
//         target: 'pino-pretty',
//         options: {
//           colorize: true,
//           translateTime: 'SYS:standard',
//           ignore: 'pid,hostname'
//         }
//       }
//     });
//   }
//
//   debug(...args: unknown[]): void {
//     this.pino.debug(this.formatMessage(args));
//   }
//
//   error(...args: unknown[]): void {
//     this.pino.error(this.formatMessage(args));
//   }
//
//   info(...args: unknown[]): void {
//     this.pino.info(this.formatMessage(args));
//   }
//
//   log(...args: unknown[]): void {
//     this.pino.info(this.formatMessage(args));
//   }
//
//   warn(...args: unknown[]): void {
//     this.pino.warn(this.formatMessage(args));
//   }
//
//   private formatMessage(args: unknown[]): string {
//     return args.map(arg =>
//       typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
//     ).join(' ');
//   }
// }

// Choose which logger to use (uncomment the one you want to use)
const logger = new SimpleCustomLogger();
// const logger = new FileLogger();
// const logger = new WinstonLoggerAdapter();
// const logger = new PinoLoggerAdapter();

const server = new FastMCP({
  logger: logger,
  name: "custom-logger-example",
  version: "1.0.0",
});

server.addTool({
  description: "A test tool that demonstrates custom logging",
  execute: async (args) => {
    return `Received: ${args.message}`;
  },
  name: "test_tool",
  parameters: z.object({
    message: z.string().describe("A message to log"),
  }),
});

// Start the server with stdio transport
server.start({ transportType: "stdio" }).catch((error: unknown) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});
