#!/usr/bin/env node
import process from "node:process";
import { run } from "../src/cli.js";

const code = run(process.argv.slice(2));
process.exit(code);
