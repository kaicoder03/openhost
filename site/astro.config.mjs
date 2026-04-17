// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  site: "https://kaicoder03.github.io",
  base: "/openhost",
  trailingSlash: "always",
  integrations: [
    starlight({
      title: "openhost",
      description:
        "Reach your self-hosted services from anywhere — end-to-end encrypted, no port forwarding, no tunnel service, no account.",
      customCss: ["./src/styles/global.css"],
      logo: { src: "./src/assets/logo.svg", replacesTitle: false },
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/kaicoder03/openhost",
        },
      ],
      sidebar: [
        {
          label: "Get started",
          items: [
            { slug: "start/what-is-openhost" },
            { slug: "start/comparison" },
          ],
        },
        {
          label: "Specification",
          autogenerate: { directory: "spec" },
        },
      ],
      disable404Route: true,
    }),
  ],
  vite: {
    plugins: [tailwindcss()],
  },
});
