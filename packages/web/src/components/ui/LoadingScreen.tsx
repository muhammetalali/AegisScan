import React from "react"
import { Shield } from "lucide-react"
export const LoadingScreen = () => (
  <div className="min-h-screen flex items-center justify-center bg-background">
    <div className="flex flex-col items-center gap-4">
      <Shield className="h-12 w-12 text-primary animate-pulse" />
      <p className="text-muted-foreground">Ã«—Ì «· Õ„Ì·...</p>
    </div>
  </div>
)
