# TCC - UNIP

## Table of Contents

- [About](#about)
- [Getting Started](#getting_started)
- [Usage](#usage)
- [Contributing](../CONTRIBUTING.md)

## Getting Started <a name = "getting_started"></a>

Primeiro, vamos navegar até o diretório do servidor e criar um **ambiente virtual** com Python:


```powershell
cd .\dashboard\server       # Navega até a pasta do servidor
python -m venv venv         # Cria um ambiente virtual chamado 'venv'
```

```powershell
.\venv\Scripts\Activate.ps1   # Ativa o ambiente virtual
```

### Configuração do Servidor FastAPI com YOLO 🚀

Este guia explica como configurar o servidor usando **FastAPI**, capturar vídeo com **OpenCV** e usar **YOLO (Ultralytics)** para detecção de objetos.

#### 1. Download de bibliotecas

No ambiente [venv](#venv) faca o importacao das bibliotecas.

```bash
pip install fastapi uvicorn
pip install opencv-python
pip install ultralytics
```

#### 2. Importando bibliotecas

Confirme a importacao das bibliotecas necessarias.

```python
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
import cv2
from ultralytics import YOLO
import threading
```

## Getting Started <a name = ""></a>

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See [deployment](#deployment) for notes on how to deploy the project on a live system.

### Prerequisites

What things you need to install the software and how to install them.

```
Give examples
```

### Installing

A step by step series of examples that tell you how to get a development env running.

Say what the step will be

```
Give the example
```

And repeat

```
until finished
```

End with an example of getting some data out of the system or using it for a little demo.

## Usage <a name = "usage"></a>

Add notes about how to use the system.
