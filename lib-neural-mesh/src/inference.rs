//! Neural network inference engine using tract-onnx
//!
//! Provides ONNX model loading and inference via the tract-onnx crate.
//! Supports any ONNX model that takes a 1-D float tensor and produces a 1-D float output.
//! Falls back gracefully when no model file is available.

use crate::error::{NeuralMeshError, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tract_onnx::prelude::*;

/// Type alias for a tract optimized ONNX model (f32 inference plan)
type TractModel = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

/// Generic inference engine for ONNX neural network models
///
/// Wraps tract-onnx to load `.onnx` files and run forward passes.
/// Thread-safe via `Arc<TractModel>` — the plan is immutable after optimization.
pub struct InferenceEngine {
    /// Optimized tract inference plan (None until a model is successfully loaded)
    model: Option<Arc<TractModel>>,

    /// Path the model was loaded from (for diagnostics)
    model_path: Option<PathBuf>,

    /// Expected input size (inferred from the model's first input fact)
    input_size: Option<usize>,
}

impl InferenceEngine {
    /// Create new inference engine (no model loaded yet)
    pub fn new() -> Self {
        Self {
            model: None,
            model_path: None,
            input_size: None,
        }
    }

    /// Load an ONNX model from disk.
    ///
    /// The model is parsed, optimized, and compiled into a `SimplePlan` that can
    /// be executed repeatedly without further allocation overhead.
    ///
    /// # Errors
    /// Returns `ModelLoadFailed` if the file cannot be read or the ONNX graph is
    /// incompatible with tract.
    pub fn load_model<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();

        // Parse the ONNX protobuf
        let raw_model = tract_onnx::onnx()
            .model_for_path(path)
            .map_err(|e| NeuralMeshError::ModelLoadFailed(
                format!("Failed to parse ONNX model at {}: {}", path.display(), e),
            ))?;

        // Try to determine expected input size from the first input fact.
        let input_size: Option<usize> = raw_model
            .input_fact(0)
            .ok()
            .and_then(|fact| {
                // as_concrete_finite() -> Result<Option<SmallVec<[usize;4]>>>
                fact.shape.as_concrete_finite().ok().flatten().map(|dims| {
                    dims.iter().copied().product::<usize>()
                })
            })
            .filter(|&s| s > 0);

        // Optimize and compile into an inference plan
        let optimized = raw_model
            .into_optimized()
            .map_err(|e| NeuralMeshError::ModelLoadFailed(
                format!("Failed to optimize ONNX model: {}", e),
            ))?;

        let plan = optimized
            .into_runnable()
            .map_err(|e| NeuralMeshError::ModelLoadFailed(
                format!("Failed to compile ONNX model into runnable plan: {}", e),
            ))?;

        self.model = Some(Arc::new(plan));
        self.model_path = Some(path.to_path_buf());
        self.input_size = input_size;

        tracing::info!(
            "Loaded ONNX model from {} (input_size={:?})",
            path.display(),
            self.input_size,
        );

        Ok(())
    }

    /// Run inference on a 1-D float input vector.
    ///
    /// The input is reshaped to match the model's expected input dimensions.
    /// If the model expects a specific size the caller must provide exactly
    /// that many elements, otherwise the call will fail.
    ///
    /// # Returns
    /// A flat `Vec<f32>` containing all values from the model's first output tensor.
    pub fn infer(&self, input: &[f32]) -> Result<Vec<f32>> {
        let plan = self.model.as_ref().ok_or_else(|| {
            NeuralMeshError::InferenceFailed("No model loaded".to_string())
        })?;

        // If we know the expected input size, validate
        if let Some(expected) = self.input_size {
            if input.len() != expected {
                return Err(NeuralMeshError::InferenceFailed(format!(
                    "Input size mismatch: model expects {} elements, got {}",
                    expected,
                    input.len(),
                )));
            }
        }

        // Build a 1-D tensor from the input slice
        let tensor = tract_ndarray::Array1::from_vec(input.to_vec())
            .into_dyn()
            .into_tensor();

        let result = plan
            .run(tvec![tensor.into()])
            .map_err(|e| NeuralMeshError::InferenceFailed(
                format!("Inference execution failed: {}", e),
            ))?;

        // Extract the first output tensor as a flat f32 vec
        let output = result
            .first()
            .ok_or_else(|| NeuralMeshError::InferenceFailed(
                "Model produced no output tensors".to_string(),
            ))?
            .to_array_view::<f32>()
            .map_err(|e| NeuralMeshError::InferenceFailed(
                format!("Failed to read output tensor as f32: {}", e),
            ))?;

        Ok(output.iter().copied().collect())
    }

    /// Check if a model has been loaded and is ready for inference
    pub fn is_loaded(&self) -> bool {
        self.model.is_some()
    }

    /// Get the path of the currently loaded model (if any)
    pub fn model_path(&self) -> Option<&Path> {
        self.model_path.as_deref()
    }

    /// Get the expected input size (if determinable from the model graph)
    pub fn expected_input_size(&self) -> Option<usize> {
        self.input_size
    }
}

impl Default for InferenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = InferenceEngine::new();
        assert!(!engine.is_loaded());
        assert!(engine.model_path().is_none());
        assert!(engine.expected_input_size().is_none());
    }

    #[test]
    fn test_inference_without_model() {
        let engine = InferenceEngine::new();
        let result = engine.infer(&[1.0, 2.0, 3.0]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("No model loaded"));
    }

    #[test]
    fn test_load_nonexistent_model() {
        let mut engine = InferenceEngine::new();
        let result = engine.load_model("/nonexistent/model.onnx");
        assert!(result.is_err());
        assert!(!engine.is_loaded());
    }
}
