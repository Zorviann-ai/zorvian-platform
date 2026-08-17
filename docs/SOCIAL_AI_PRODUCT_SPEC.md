# Zorvian Social AI — Product & Delivery Specification

## Goal
Build Social AI first as a client-ready social media operating workspace, while preserving a clean integration point to the standalone Zorvian Video AI product.

## Client workflow
1. Connect owned social accounts using provider OAuth. Never request social passwords.
2. Create a campaign or one-off post from a business objective.
3. Choose target networks and content type: text, image, video, or Let Zorvian decide.
4. Generate a distinct platform-aware version for each selected network.
5. Preview each version in an identifiable network-style card.
6. Edit/regenerate individual variants without destroying approved variants.
7. Explicitly choose Save Draft, Approve, Post Now, or Schedule.
8. For Schedule: choose date, time, timezone and networks, then confirm.
9. Publish through provider adapters; record provider IDs, status, attempts and errors.
10. Display calendar/history and later analytics.

## Networks
Initial adapter architecture: LinkedIn, Facebook, Instagram and X. TikTok and YouTube are provider adapters that can be enabled after their permissions/audit requirements are satisfied.

## Connected Accounts
Each account record must expose provider, display/account/page name, connection status, permission/scopes status, token-health status and disconnect/reconnect controls. OAuth credentials/tokens are server-side secrets and must not be returned to the browser.

## Post composer
Required inputs/controls:
- business objective
- campaign/post type
- audience
- networks
- content type: text / image / video / auto
- brand voice
- CTA
- media upload/library
- Video AI action

Output must be structured customer-facing data only: headline/hook, caption/body, CTA, hashtags, media recommendation, platform and warnings. Internal reasoning, system prompts and model scratchpad content must never be rendered or returned as display content.

## Approval safety
No provider publishing call may occur merely because AI generation succeeded. A user must explicitly choose Post Now or confirm a Schedule action. Generation and publishing are separate operations.

## Scheduler
Store UTC execution time plus the client's timezone. Scheduled jobs must be idempotent and have stable delivery keys so retries cannot create duplicate posts. States: draft, generated, approved, scheduled, publishing, published, failed, cancelled.

## Core data model
- social_accounts
- social_campaigns
- social_posts
- social_post_variants
- social_media_assets
- social_schedules
- social_publish_attempts
- social_metrics (later phase)

## Video AI integration contract
Social AI must not implement long-form video processing itself. It integrates with standalone Zorvian Video AI through a stable internal project/asset contract.

Composer actions:
- Create with Video AI
- Choose existing Video AI project/asset
- Send campaign brief to Video AI

Social sends: campaign ID, objective, audience, target networks, desired duration/aspect ratio, brand context and callback/return context.

Video AI returns an approved asset reference plus metadata (duration, aspect ratio, thumbnail/poster, captions availability and renditions). Social stores the asset reference, not duplicate processing logic.

This permits Video AI to independently support weddings, corporate events and other 20–30+ minute editing/enhancement projects while Social AI can request or consume short social-ready derivatives.

## Acceptance gate before Social AI is signed off
- no internal reasoning visible in UI/API display responses
- account connection UI and secure server-side OAuth model
- platform-specific generation and preview
- explicit approval before publish
- Post Now and Schedule flows
- calendar/status/history
- idempotent delivery/retry behaviour
- clear provider failure state; never fabricate success
- Video AI integration action and contract present even before the Video AI processing engine is built
- existing Receptionist, Calendar, Booking and Leads behaviour must not regress

## Build order
1. Social response sanitation and structured result contract.
2. Social account/provider adapter model.
3. Campaign/composer and network-specific variants.
4. Approval, scheduler, publishing job model and calendar.
5. Video AI integration surface/contract.
6. Live provider OAuth/publishing adapters as credentials and provider approvals are configured.
7. Only after Social AI passes its gate, begin standalone Video AI implementation.
