import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Languages } from "lucide-react";
import { setLocale } from "@/paraglide/runtime";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { setLocaleCookie } from "@/lib/i18n";

export function LanguageToggle() {
  const navigate = useNavigate();
  const location = useLocation();


  const handleLanguageChange = (newLocale: "en" | "zh-CN") => {
    // Set cookie first
    setLocaleCookie(newLocale);
    
    // If we are on the homepage (root / or /$lang)
    // We should strictly navigate to the localized path to ensure the "path strategy" is respected visually
    // However, for other pages, we just reload/set state because they are cookie-based.
    
    // Check if we are on homepage path (either "/" or "/en" or "/zh-CN")
    const isHomepage = location.pathname === "/" || location.pathname === "/en" || location.pathname === "/zh-CN";

    if (isHomepage) {
         // If switching to default locale (en) from something else, ideally we go to '/' or '/en'? 
         // The user path strategy was: "homepage based on path, others based on cookie".
         // Let's explicitly navigate to /$lang for clarity, or / for default?
         // Let's use /$lang for explicit language selection to be safe.
         navigate({ to: '/$lang', params: { lang: newLocale } });
    } else {
        // For other pages, just use the runtime setLocale which handles reload if configured, 
        // or we manually reload if needed to pick up the new cookie.
        setLocale(newLocale);
    }
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon">
          <Languages className="h-[1.2rem] w-[1.2rem]" />
          <span className="sr-only">Change language</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => handleLanguageChange("en")}>
          English
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => handleLanguageChange("zh-CN")}>
          中文 (简体)
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
