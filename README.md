# Tarea 3: Miner de vulnerabilidades para organizaciones de GitHub

Herramienta de línea de comandos que recibe el nombre de una organización de
GitHub, clona sus repositorios, ejecuta un análisis estático de seguridad con
**CodeQL** sobre cada uno y consolida todos los resultados en un único archivo
JSON.

Flujo general:

```
Organización GitHub → API de GitHub → repositorios → clonación → CodeQL →
SARIF → modelos Pydantic → JSON consolidado
```
## Instalación

1. Clona este repositorio y entra a la carpeta del proyecto.
2. Crea y activa un entorno virtual:
   ```bash
   python3 -m venv venv
   source venv/bin/activate       # Linux/Mac
   venv\Scripts\activate          # Windows
   ```
3. Instala las dependencias:
   ```bash
   pip install -e .
   ```
   (equivalente a `pip install -r REQUIREMENTS.txt` si prefieres ese archivo).
4. Instala **CodeQL CLI** por separado (no se instala vía pip). Descarga el
   bundle oficial desde el repositorio de CodeQL de GitHub y agrégalo a tu
   `PATH`. Verifica la instalación con:
   ```bash
   codeql --version
   ```

## Configuración del token de GitHub

1. Genera un token classic con el scope `public_repo` (suficiente para
   organizaciones públicas).
2. Copia `.env.example` a `.env`:
   ```bash
   cp .env.example .env
   ```
3. Pega tu token en `.env`:
   ```
   GITHUB_TOKEN=ghp_tu_token_aqui
   ```
4. Carga la variable de entorno antes de ejecutar el miner (por ejemplo con
   `export $(cat .env | xargs)` en bash, o usando `python-dotenv` si prefieres
   cargarla automáticamente desde el código).

## Uso

El comando principal es `scan`:

```bash
python -m miner.cli --organization <organizacion> --output <archivo.json>
```

### Analizar todos los repositorios de una organización

```bash
python -m miner.cli --organization pallets-eco --output results.json
```

### Analizar solo una cantidad limitada de repositorios (pruebas rápidas)


```bash
python -m miner.cli --organization pallets-eco --output test.json --max-repos N
```

## Ejecutar las pruebas

```bash
pytest tests/ -v
```