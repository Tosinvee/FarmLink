/* eslint-disable prettier/prettier */
import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';

@Injectable()
export class PaystackService {
  private readonly secretKey: string;
  private readonly baseUrl: string;
  private readonly callbackUrl?: string;

  constructor(config: ConfigService) {
    this.secretKey = config.get<string>('PAYSTACK_SECRET_KEY') || '';
    this.baseUrl =
      config.get<string>('PAYSTACK_BASE_URL') || 'https://api.paystack.co';
    this.callbackUrl = config.get<string>('PAYSTACK_CALLBACK_URL');
  }

  getSecretKey() {
    return this.secretKey;
  }

  private assertConfigured() {
    if (!this.secretKey || this.secretKey === 'YOUR_PAYSTACK_SECRET_KEY') {
      throw new ServiceUnavailableException(
        'Paystack is not configured. Set PAYSTACK_SECRET_KEY.',
      );
    }
  }

  private get client() {
    return axios.create({
      baseURL: this.baseUrl,
      timeout: 15000,
      headers: {
        Authorization: `Bearer ${this.secretKey}`,
        'Content-Type': 'application/json',
      },
    });
  }

  async initializePayment(
    email: string,
    amountKobo: number,
    reference: string,
    metadata?: Record<string, unknown>,
  ) {
    this.assertConfigured();

    const { data } = await this.client.post('/transaction/initialize', {
      email,
      amount: amountKobo,
      reference,
      ...(this.callbackUrl ? { callback_url: this.callbackUrl } : {}),
      ...(metadata ? { metadata } : {}),
    });

    if (!data?.status || !data?.data) {
      throw new ServiceUnavailableException(
        data?.message || 'Paystack initialize failed',
      );
    }

    return data.data as {
      authorization_url: string;
      access_code: string;
      reference: string;
    };
  }

  async verifyPayment(reference: string) {
    this.assertConfigured();

    const { data } = await this.client.get(
      `/transaction/verify/${encodeURIComponent(reference)}`,
    );

    if (!data?.status || !data?.data) {
      throw new ServiceUnavailableException(
        data?.message || 'Paystack verification failed',
      );
    }

    return data.data as {
      status: string;
      amount: number;
      reference: string;
    };
  }
}