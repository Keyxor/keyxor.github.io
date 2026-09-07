---
title: "{{ replace .File.ContentBaseName "-" " " | title }} — Speedrun"
date: {{ .Date }}
draft: true
tier: speedrun
summary: ""
categories:
  - Offensive
tags:
  - {{ replace .File.ContentBaseName "-" " " | title }}
  - Hack The Box
  - Linux
ShowToc: true
TocOpen: false
---

Commands and output, one line per step. The reasoning, the dead ends, and why
each pivot was chosen are in the [long version]({{`{{< relref "/writeups/offensive/SLUG" >}}`}}).

Target: `10.10.10.10`, attacker: `10.10.14.1`.

## Recon

## Foothold

## Privilege escalation

## Chain summary

1. One line per step, start to root.
