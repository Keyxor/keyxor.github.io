---
title: "{{ replace .File.ContentBaseName "-" " " | title }}"
date: {{ .Date }}
draft: true
summary: ""
# Categories are the topic axis: Offensive, Defensive, or both when the
# writeup covers a technique and the telemetry it leaves behind.
categories:
  - Offensive
# Tags are everything else: platform, target OS, techniques.
tags:
  - Hack The Box
  - Linux
ShowToc: true
TocOpen: true
---

## Overview

Short description of the target and core techniques.

## Enumeration

Fenced code block with the scan (for example: nmap -sC -sV -p- <ip>), then explain findings rather than only pasting output.

## Web Enumeration

Methodology and important discoveries.

<!-- Screenshots live in this folder, next to index.md, and are referenced by
     filename alone. Add them with scripts/add-screenshot.sh so metadata is
     stripped before the file is committed. -->
![Initial application](application.png)

## Initial Access

The vulnerability, reasoning, exploitation, and result.

## Privilege Escalation

Path to elevated privileges.

## Key Takeaways

1. Lesson one.
2. Lesson two.
3. Lesson three.
