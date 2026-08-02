declare module "mailparser" {
  export interface Attachment {
    filename?: string;
    contentType?: string;
    content?: Uint8Array | Buffer | string;
    size?: number;
  }
  export interface ParsedMail {
    attachments?: Attachment[];
    from?: { text?: string } | string;
    subject?: string;
    [key: string]: unknown;
  }
  export function simpleParser(input: string | Buffer): Promise<ParsedMail>;
}
