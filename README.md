# Tarea 3/ Tarea 4: Miner de vulnerabilidades y SBOMs para organizaciones de GitHub

Herramienta de línea de comandos que recibe el nombre de una organización de
GitHub, clona sus repositorios, ejecuta un análisis estático de seguridad con
**CodeQL** sobre cada uno y consolida todos los resultados en un único archivo
JSON. Además, utilizando **Syft** genera un SBOM por repositorio dando los resultados en un archivo JSON

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
5. Instala **Syft**:
   ```bash
   curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin

   ```

   verifica la instalación con:
   ```bash
   syft --version
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

## Uso CodeQL

El comando para utilizar CodeQL es `scan`:

```bash
python -m miner.cli scan --organization <organizacion> --output <archivo.json>
```

### Analizar todos los repositorios de una organización

```bash
python -m miner.cli scan --organization pallets-eco --output results.json
```

### Analizar solo una cantidad limitada de repositorios (pruebas rápidas)


```bash
python -m miner.cli scan --organization pallets-eco --output test.json --max-repos N
```
## Uso Syft
Generación de SBOM en formato CycloneDX JSON por cada repositorio sin ejecutar CodeQL. 
Comando sin clonar repositorio ya clonados si se utilizó *scan*:
```bash
python -m miner.cli sbom \
  --organization <organizacion> \
  --output <archivo-consolidado.json> \
  --sbom-dir <carpeta-de-sboms> \
  --workspace-dir <carpeta-de-repos-clonados>
```

### Analizar una organización completa 
 
```bash
python -m miner.cli sbom \
  --organization pallets-eco \
  --output sbom-results.json \
  --sbom-dir sboms \
  --workspace-dir workspace
```

### Ejemplo usando pocos repositorios

```bash
python -m miner.cli sbom --organization pallets-eco --output sbom-test.json --max-repos 3
```

### Archivos de salida
   1. **Un SBOM por repositorio** en formato CycloneDX JSON, guardado en `<sbom-dir>/<nombre-repo>.cdx.json` 
      Contiene el inventario completo de componentes identificados por Syft.
   2. **Un JSON consolidado** (`sbom-results.json`), con un resumen por repositorio.

### Verificación manual
El inventario de un SBOM depende de qué archivos de declaración/bloqueo de
dependencias existan en el repositorio y de qué pueda reconocer Syft; es
normal que no coincida 1:1 con un archivo de dependencias directo. Para contrastar manualmente:
 
```bash
# Ver los componentes reportados en un SBOM (requiere jq)
cat sboms/<nombre-repo>.cdx.json | jq '.components[] | {name, version}'
 
# Compararlo con el archivo de dependencias real del repo clonado
cat workspace/<nombre-repo>/requirements.txt      # proyectos Python
cat workspace/<nombre-repo>/package.json          # proyectos Node.js
cat workspace/<nombre-repo>/package-lock.json
```

## Ejecutar las pruebas

```bash
pytest tests/ -v
```