import { useState } from "react";
import { Copy, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function JsonViewer({
  data,
  className,
  maxHeight = "400px",
}: {
  data: any;
  className?: string;
  maxHeight?: string;
}) {
  const [copied, setCopied] = useState(false);
  const text = typeof data === "string" ? data : JSON.stringify(data, null, 2);

  function copy() {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    });
  }

  if (data === null || data === undefined) {
    return (
      <div
        className={cn(
          "rounded-md border border-border bg-muted/30 p-4 text-sm text-muted-foreground",
          className,
        )}
      >
        No data
      </div>
    );
  }

  return (
    <div className={cn("relative rounded-md border border-border bg-card", className)}>
      <Button
        size="sm"
        variant="ghost"
        onClick={copy}
        className="absolute right-2 top-2 h-7 px-2 text-xs"
      >
        {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
      </Button>
      <pre
        className="overflow-auto p-4 text-xs leading-relaxed text-foreground/90 font-mono"
        style={{ maxHeight }}
      >
        {text}
      </pre>
    </div>
  );
}
