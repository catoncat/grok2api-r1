export function SiteFooter() {
  return (
    <footer className="mx-auto flex h-10 w-full max-w-[1280px] shrink-0 items-center justify-end gap-1.5 whitespace-nowrap px-5 text-right text-[11px] text-muted-foreground sm:px-8">
      <a className="transition-colors hover:text-foreground" href="https://github.com/chenyme/grok2api" target="_blank" rel="noreferrer">Grok2API</a>
      <span>© 2026</span>
      <span aria-hidden="true">·</span>
      <span>Built by</span>
      <a className="transition-colors hover:text-foreground" href="https://blog.cheny.me/" target="_blank" rel="noreferrer">Chenyme</a>
    </footer>
  );
}
