export interface User {
  id: number;
  username: string;
  email: string;
  twoFactorEnabled: boolean;
  createdAt: string;
}

export interface SecurityLog {
  id: string;
  timestamp: string;
  type: 'info' | 'success' | 'warning' | 'danger';
  event: string;
  details: string;
}

export interface SqlQueryResponse {
  queryUsed: string;
  success: boolean;
  resultsCount: number;
  results: any[];
  error?: string;
  vulnerableToInjection: boolean;
}

export interface SqlInjectionComparison {
  raw: SqlQueryResponse;
  parameterized: SqlQueryResponse;
}
