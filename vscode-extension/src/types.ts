export interface ChainVetFinding {
  kind: string;
  layer?: string;
  severity?: string;
  confidence?: string;
  category?: string;
  function?: string;
  file?: string;
  start?: number;
  end?: number;
  message: string;
  evidence?: string;
}
