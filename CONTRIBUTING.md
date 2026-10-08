# Contribuire

Le liste in `dist/` sono **generate**: non si modificano mai a mano. Si modificano le sorgenti e il build (GitHub Actions) rigenera tutto.

## Dove intervenire

| Cosa | File |
|---|---|
| Bloccare un dominio | `domains/blocklist/<categoria>.txt` |
| Sbloccare un host (falso positivo) | `domains/allowlist/<categoria>.txt` |
| Proteggere un servizio critico | `domains/allowlist/protetti.txt` |
| Bloccare un IP | `ip/custom/<categoria>.txt` |
| Sbloccare un IP | `ip/allowlist.txt` |
| Rete di hosting/CDN condivisa | `ip/condivisi.txt` |
| Nuova fonte | `ip/sources.toml` o `domains/domains.toml` |

## Formato delle voci

Una voce per riga:

```
voce | AAAA-MM-GG | motivo | ticket (o -) | scadenza AAAA-MM-GG (opzionale)
```

## Regole

1. **Nessun dato personale**: nel motivo solo descrizione tecnica e ID del ticket. La CI rifiuta email e numeri di telefono.
2. **Nessuna regola per singolo cliente** (`$client`) e nessun nome o IP di clienti: il repository è pubblico.
3. **Allowlist chirurgiche**: solo l'host esatto che si è rotto, mai il dominio intero di un vendor. Un'allowlist non può contraddire una nostra blocklist né sbloccare servizi di bypass DNS/VPN: build e CI lo verificano.
4. **Fonti nuove solo con licenza verificata**, compatibile con GPL-3.0 e con l'uso commerciale. Escluse le licenze non commerciali (NC) e le fonti senza licenza.
5. **Mai bloccare per IP un'infrastruttura condivisa** (CDN, hosting): aggiungerla a `ip/condivisi.txt`.
6. Ogni modifica passa da una **pull request**: la CI esegue validazione e test (`tests/test_liste.py`).

## Verifiche in locale

```
python scripts/build_ip.py --check
python scripts/build_domains.py --check
python tests/test_liste.py
```

I test scaricano le fonti e riscrivono i file generati nella copia di lavoro: non committare `dist/`.

## Segnalazioni

Usa i moduli delle issue: *Segnala un falso positivo* o *Proponi un blocco*. Per problemi di sicurezza vedi [SECURITY.md](SECURITY.md).
