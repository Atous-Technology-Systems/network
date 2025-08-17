# API Reference

## Table of Contents

1. [Core Module](#core-module)
   - [ModelManager](#modelmanager)
2. [Network Module](#network-module)
   - [LoraAdaptiveEngine](#loraadaptiveengine)
   - [ChurnMitigation](#churnmitigation)
3. [Security Module](#security-module)
   - [ABISSSystem](#abisssystem)
   - [NNISSystem](#nnissystem)

## Core Module

### ModelManager

The main class for managing machine learning models.

#### Methods

- `__init__(config: Optional[Dict[str, Any]] = None)`
  - Initialize with configuration

- `download_model(source_url: str, model_path: str, **kwargs) -> bool`
  - Download a model from the given URL

- `check_for_updates(aggregation_server: str) -> bool`
  - Check for model updates

- `rollback_version(version: str) -> bool`
  - Roll back to a previous version

## Network Module

### LoraAdaptiveEngine

Optimiza comunicação LoRa e parâmetros dinâmicos.

#### Methods

- `send(data: bytes) -> int`
  - Send data over LoRa

- `receive() -> bytes`
  - Receive data from LoRa

### ChurnMitigation

Handles peer-to-peer network recovery and churn mitigation.

#### Methods

- `detect_network_partitions() -> List[Set[str]]`
  - Detect network partitions

## Security Module

### ABISSSystem

Advanced Behavioral and Intrusion Security System.

#### Methods

- `analyze_behavior(behavior_data: Dict) -> Dict`
  - Analyze behavior patterns

### NNISSystem

Neural Network Immune System for threat response and memory.

#### Methods

- `match(indicators: List[Any]) -> bool`
  - Check if indicators match the threat pattern
