# Juice Shop

[juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) `v20.3.0`: TypeScript, Express and Angular.

Answer key: the project's own `// vuln-code-snippet vuln-line` comments, 27 lines (`test/` and `data/static/codefixes/` excluded). A line counts as found when a larpcop security finding lies within three lines of it in the same file. Juice Shop was the development suite: `no-bypass-security-trust`, `no-directory-listing`, `no-weak-hash`, `no-mongo-where` and `taint-redirect` were added after its first run, so the result is not a held-out number.

| Line | Vulnerability | larpcop |
|---|---|---|
| `frontend/src/app/app.routing.ts:79` | adminSectionChallenge | – |
| `frontend/src/app/app.routing.ts:186` | scoreBoardChallenge | – |
| `frontend/src/app/app.routing.ts:239` | web3SandboxChallenge | – |
| `frontend/src/app/app.routing.ts:261` | tokenSaleChallenge | – |
| `frontend/src/app/app.routing.ts:300` | tokenSaleChallenge | – |
| `frontend/src/app/search-result/search-result.component.ts:113` | restfulXssChallenge | `no-bypass-security-trust` |
| `frontend/src/app/search-result/search-result.component.ts:146` | localXssChallenge, xssBonusChallenge | `no-bypass-security-trust` |
| `lib/insecurity.ts:124` | redirectCryptoCurrencyChallenge | – |
| `lib/insecurity.ts:125` | redirectCryptoCurrencyChallenge | – |
| `lib/insecurity.ts:126` | redirectCryptoCurrencyChallenge | – |
| `lib/insecurity.ts:136` | redirectChallenge | – |
| `models/user.ts:73` | weakPasswordChallenge | – |
| `routes/chat.ts:179` | chatbotPromptInjectionChallenge, chatbotGreedyInjectionChallenge | – |
| `routes/chat.ts:184` | chatbotPromptInjectionChallenge | – |
| `routes/login.ts:34` | loginAdminChallenge, loginBenderChallenge, loginJimChallenge | `no-sql-interpolation`, `taint-sql`, `validate-request-input` |
| `routes/search.ts:23` | unionSqlInjectionChallenge, dbSchemaChallenge | `no-sql-interpolation`, `taint-sql`, `validate-request-input` |
| `routes/updateProductReviews.ts:16` | forgedReviewChallenge | `validate-request-input` |
| `routes/updateProductReviews.ts:18` | noSqlReviewsChallenge, forgedReviewChallenge | `validate-request-input` |
| `routes/updateProductReviews.ts:20` | noSqlReviewsChallenge | `validate-request-input` |
| `server.ts:290` | directoryListingChallenge | `no-directory-listing` |
| `server.ts:291` | directoryListingChallenge | `no-directory-listing` |
| `server.ts:302` | accessLogDisclosureChallenge | `no-directory-listing` |
| `server.ts:304` | accessLogDisclosureChallenge | `no-directory-listing` |
| `server.ts:374` | resetPasswordMortyChallenge | – |
| `server.ts:398` | changeProductChallenge | – |
| `server.ts:539` | registerAdminChallenge | – |
| `server.ts:759` | exposedMetricsChallenge | – |

- larpcop: 11/27 lines; 436 security findings: validate-request-input 236, secrets 69, no-directory-listing 34, no-bypass-security-trust 15, no-sql-interpolation 13, taint-sql 13, tf-open-ingress 10, gha-unpinned-action 7, no-mongo-where 7, taint-path 6, taint-nosql 5, no-eval 4, dependency-vulnerability 4, taint-log 3, gha-script-injection 2, no-inner-html 2, no-weak-hash 2, gha-curl-pipe-shell 1, taint-ssrf 1, taint-redirect 1, taint-code 1

Missed: 16 lines. They are logic, authorization or configuration flaws (exposed admin routes, a redirect allow-list built on `includes`, rate limiting that trusts `X-Forwarded-For`, chatbot prompt injection and similar), which rules matching code patterns do not model.
