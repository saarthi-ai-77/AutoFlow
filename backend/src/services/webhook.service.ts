import { logger } from '@/utils/logger';
import { cacheService } from '@/utils/redis-cache';
import crypto from 'crypto';

export interface WebhookPayload {
  id: string;
  event: string;
  data: any;
  timestamp: Date;
  signature?: string;
}

export interface WebhookDelivery {
  id: string;
  webhookId: string;
  url: string;
  payload: WebhookPayload;
  status: 'pending' | 'success' | 'failed';
  attempts: number;
  maxAttempts: number;
  nextRetryAt?: Date;
  lastError?: string;
  createdAt: Date;
  updatedAt: Date;
}

export class WebhookService {
  private readonly maxRetries = 5;
  private readonly baseDelay = 1000; // 1 second
  private readonly idempotencyTtl = 24 * 60 * 60; // 24 hours in seconds

  async sendWebhook(
    webhookId: string,
    url: string,
    payload: WebhookPayload,
    idempotencyKey?: string
  ): Promise<WebhookDelivery> {
    const deliveryId = crypto.randomUUID();

    // Check idempotency if key provided
    if (idempotencyKey) {
      const existingDelivery = await this.checkIdempotency(idempotencyKey, webhookId);
      if (existingDelivery) {
        logger.info('Webhook already processed', { deliveryId, idempotencyKey, webhookId });
        return existingDelivery;
      }
    }

    const delivery: WebhookDelivery = {
      id: deliveryId,
      webhookId,
      url,
      payload,
      status: 'pending',
      attempts: 0,
      maxAttempts: this.maxRetries,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    // Store idempotency key if provided
    if (idempotencyKey) {
      await this.storeIdempotencyKey(idempotencyKey, delivery);
    }

    // Attempt to send webhook
    await this.attemptDelivery(delivery);

    return delivery;
  }

  private async checkIdempotency(idempotencyKey: string, webhookId: string): Promise<WebhookDelivery | null> {
    try {
      const cached = await cacheService.get(`webhook:idempotency:${idempotencyKey}`);
      if (cached && cached.webhookId === webhookId) {
        return cached.delivery;
      }
    } catch (error) {
      logger.warn('Failed to check idempotency', { error, idempotencyKey });
    }
    return null;
  }

  private async storeIdempotencyKey(idempotencyKey: string, delivery: WebhookDelivery): Promise<void> {
    try {
      await cacheService.set(
        `webhook:idempotency:${idempotencyKey}`,
        { webhookId: delivery.webhookId, delivery },
        this.idempotencyTtl
      );
    } catch (error) {
      logger.error('Failed to store idempotency key', { error, idempotencyKey });
    }
  }

  private async attemptDelivery(delivery: WebhookDelivery): Promise<void> {
    delivery.attempts++;

    try {
      const response = await fetch(delivery.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'AutoFlow-Webhook/1.0',
          'X-Webhook-ID': delivery.webhookId,
          'X-Delivery-ID': delivery.id,
          'X-Attempt': delivery.attempts.toString(),
        },
        body: JSON.stringify(delivery.payload),
      });

      if (response.ok) {
        delivery.status = 'success';
        logger.info('Webhook delivered successfully', {
          deliveryId: delivery.id,
          webhookId: delivery.webhookId,
          attempt: delivery.attempts,
          statusCode: response.status
        });
      } else {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
    } catch (error) {
      delivery.status = 'failed';
      delivery.lastError = error instanceof Error ? error.message : 'Unknown error';

      if (delivery.attempts < delivery.maxAttempts) {
        // Schedule retry with exponential backoff
        const delay = this.baseDelay * Math.pow(2, delivery.attempts - 1);
        delivery.nextRetryAt = new Date(Date.now() + delay);
        delivery.status = 'pending';

        logger.warn('Webhook delivery failed, scheduling retry', {
          deliveryId: delivery.id,
          attempt: delivery.attempts,
          nextRetryAt: delivery.nextRetryAt,
          error: delivery.lastError
        });

        // In a real implementation, you'd queue this for later retry
        setTimeout(() => this.attemptDelivery(delivery), delay);
      } else {
        logger.error('Webhook delivery failed permanently', {
          deliveryId: delivery.id,
          attempts: delivery.attempts,
          error: delivery.lastError
        });
      }
    }

    delivery.updatedAt = new Date();
  }

  async retryFailedWebhooks(): Promise<void> {
    // In a real implementation, you'd query the database for failed deliveries
    // and retry them. For now, this is a placeholder.
    logger.info('Checking for failed webhooks to retry');
  }
}

export const webhookService = new WebhookService();