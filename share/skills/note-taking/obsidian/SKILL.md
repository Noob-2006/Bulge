---
upstream: "hermes-agent/skills/note-taking/obsidian (MIT)"
name: obsidian
description: Read, search, create, and edit notes in the Obsidian vault.
version: 1.0.0
author: Teknium (teknium1), Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [Obsidian, Notes, Markdown, Vault]
    related_skills: []
---
# Obsidian Vault

Use this skill for filesystem-first Obsidian vault work: reading notes, listing notes, searching note files, creating notes, appending content, and adding wikilinks.

## Vault path

Use a known or resolved vault path before calling file tools.

The documented vault-path convention is the `OBSIDIAN_VAULT_PATH` environment variable, for example from `${HERMES_HOME:-~/.hermes}/.env`. If it is unset, use `~/Documents/Obsidian Vault`.

File tools do not expand shell variables. Do not pass paths containing `$OBSIDIAN_VAULT_PATH` to `read_file`, `write_file`, `patch`, or `search_files`; resolve the vault path first and pass a concrete absolute path. Vault paths may contain spaces, which is another reason to prefer file tools over shell commands.

If the vault path is unknown, `terminal` is acceptable for resolving `OBSIDIAN_VAULT_PATH` or checking whether the fallback path exists. Once the path is known, switch back to file tools.

## Read a note

Use `read_file` with the resolved absolute path to the note. Prefer this over `cat` because it provides line numbers and pagination.

## List notes

Use `search_files` with `target: "files"` and the resolved vault path. Prefer this over `find` or `ls`.

- To list all markdown notes, use `pattern: "*.md"` under the vault path.
- To list a subfolder, search under that subfolder's absolute path.

## Search

Use `search_files` for both filename and content searches. Prefer this over `grep`, `find`, or `ls`.

- For filenames, use `search_files` with `target: "files"` and a filename `pattern`.
- For note contents, use `search_files` with `target: "content"`, the content regex as `pattern`, and `file_glob: "*.md"` when you want to restrict matches to markdown notes.

## Create a note

Use `write_file` with the resolved absolute path and the full markdown content. Prefer this over shell heredocs or `echo` because it avoids shell quoting issues and returns structured results.

## Append to a note

Prefer a native file-tool workflow when it is not awkward:

- Read the target note with `read_file`.
- Use `patch` for an anchored append when there is stable context, such as adding a section after an existing heading or appending before a known trailing block.
- Use `write_file` when rewriting the whole note is clearer than constructing a fragile patch.

For an anchored append with `patch`, replace the anchor with the anchor plus the new content.

For a simple append with no stable context, `terminal` is acceptable if it is the clearest safe option.

## Targeted edits

Use `patch` for focused note changes when the current content gives you stable context. Prefer this over shell text rewriting.

## Wikilinks

Obsidian links notes with `[[Note Name]]` syntax. When creating notes, use these to link related content.

## OpenClaw procedure (upstream `openclaw/skills/obsidian`, MIT, verbatim)

Use the official `obsidian` CLI for Obsidian vault work. Vault files are plain Markdown, so direct file edits are still fine when safer/faster.

### Requirements

- Obsidian 1.12.7+ installed.
- Settings -> General -> Command line interface enabled.
- `obsidian` registered on PATH.
- Obsidian app running; the CLI connects to the running app.

Check:

```bash
obsidian version
obsidian help
```

macOS registration creates `/usr/local/bin/obsidian` pointing at the app-bundled CLI. Linux registration copies the binary to `~/.local/bin/obsidian`.

### Vault model

- Notes: `*.md`.
- Config: `.obsidian/`; avoid editing unless asked.
- Canvases: `*.canvas` JSON.
- Attachments: vault-configured folder.
- Multiple vaults are common; pass `vault="<name>"` when ambiguous.

Obsidian desktop tracks vaults here:

- `~/Library/Application Support/obsidian/obsidian.json`

### Command pattern

```bash
obsidian <command> [name=value] [flag]
obsidian vault="Notes" search query="meeting notes" format=json
```

Parameter values with spaces need quotes. Add `--copy` to copy output where useful.

### Common commands

Open/read:

```bash
obsidian open file=Recipe
obsidian open path="Inbox/Idea.md" newtab
obsidian read
obsidian read file=Recipe
```

Search:

```bash
obsidian search query="TODO" matches
obsidian search query="status::active" format=json
obsidian search:open query="project notes"
```

Create/modify:

```bash
obsidian create name="New Note"
obsidian create path="Inbox/Idea.md" content="# Idea"
obsidian append file=Note content="New line"
obsidian prepend file=Note content="After frontmatter"
```

Move/delete:

```bash
obsidian move file=Note to=Archive/
obsidian move path="Inbox/Old.md" to="Projects/New.md"
obsidian delete file=Note
```

Daily/tasks:

```bash
obsidian daily
obsidian daily:read
obsidian daily:append content="- [ ] Review inbox"
obsidian tasks all todo
obsidian task file=Note line=8 done
```

Properties/links:

```bash
obsidian tags all counts
obsidian property:read file=Note name=status
obsidian property:set file=Note name=status value=done
obsidian backlinks file=Note
obsidian unresolved verbose counts
```

Developer/debug:

```bash
obsidian plugin:reload my-plugin
obsidian dev:errors
obsidian dev:screenshot file=shot.png
obsidian eval "app.vault.getFiles().length"
```

### Notes

- `file=<name>` uses Obsidian-style file resolution; `path=<vault-relative.md>` is exact.
- Prefer CLI move/delete/property commands for Obsidian-aware updates.
- Prefer direct Markdown edits for bulk text changes after locating the vault path.
- Do not rely on third-party `obsidian-cli` unless user explicitly asks for it.

> Transcribed from `openclaw/skills/obsidian/SKILL.md` (MIT, © OpenClaw contributors). OpenClaw-only runtime hooks (gateway service env, session URLs, OpenClaw node/pairing state) apply only under OpenClaw; the commands, flags and safety notes are portable.
