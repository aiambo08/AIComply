module.exports = {
            content: [__dirname + "/app.html", __dirname + "/app.js"],
            darkMode: "class",
            theme: {
                extend: {
                    colors: {
                        "obsidian": "#07090e",
                        "slate-card": "#0e121a",
                        "slate-card-hover": "#141a26",
                        "border-slate": "#1b2333",
                        "border-slate-bright": "#2d3748",
                        "cyber-emerald": "#00f59b",
                        "alert-amber": "#ffb800",
                        "hazard-crimson": "#ff3355",
                        "neon-cyan": "#00d2ff",
                        "neon-violet": "#c4abff",
                        "text-primary": "#f8fafc",
                        "text-secondary": "#94a3b8",
                        "text-muted": "#64748b"
                    },
                    fontFamily: {
                        "headline": ["system-ui", "sans-serif"],
                        "body": ["system-ui", "sans-serif"],
                        "mono": ["ui-monospace", "monospace"]
                    }
                }
            }
        }