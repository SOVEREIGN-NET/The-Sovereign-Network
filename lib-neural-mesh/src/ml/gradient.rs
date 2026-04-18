//! Numerical gradient utilities for ML training
//!
//! Provides shared finite-difference gradient macros used by PPO, LSTM, and
//! REINFORCE implementations. Each weight/bias is perturbed by ±ε to estimate
//! the gradient, then updated with `w -= lr * ∂L/∂w`.
//!
//! These are macros (not functions) so that the borrow checker sees the
//! sequential mutate→read→mutate→read pattern inline, avoiding the
//! simultaneous `&mut field` + `&self` conflict that a function call would
//! create.
//!
//! This is O(params × loss_eval) per call — acceptable for our small networks
//! (< 50K params) but should be replaced with proper backpropagation if models
//! grow significantly.

/// Update a 2D weight matrix using central finite-difference gradients.
///
/// For each element `w[r,c]`:
///   gradient ≈ (loss(w+ε) - loss(w-ε)) / (2ε)
///   w[r,c] -= lr * gradient
///
/// # Usage
/// ```ignore
/// update_matrix_fd!(self.w_out, eps, lr, compute_loss(self));
/// ```
macro_rules! update_matrix_fd {
    ($mat:expr, $eps:expr, $lr:expr, $loss:expr) => {{
        let __eps: f32 = $eps;
        let __lr: f32 = $lr;
        let (__rows, __cols) = ($mat.nrows(), $mat.ncols());
        for __r in 0..__rows {
            for __c in 0..__cols {
                let __orig = $mat[[__r, __c]];
                $mat[[__r, __c]] = __orig + __eps;
                let __lp: f32 = $loss;
                $mat[[__r, __c]] = __orig - __eps;
                let __lm: f32 = $loss;
                $mat[[__r, __c]] = __orig - __lr * ((__lp - __lm) / (2.0 * __eps));
            }
        }
    }};
}
pub(crate) use update_matrix_fd;

/// Update a 1D bias slice using central finite-difference gradients.
///
/// # Usage
/// ```ignore
/// update_bias_fd!(self.b_out, eps, lr, compute_loss(self));
/// ```
macro_rules! update_bias_fd {
    ($bias:expr, $eps:expr, $lr:expr, $loss:expr) => {{
        let __eps: f32 = $eps;
        let __lr: f32 = $lr;
        let __len = $bias.len();
        for __i in 0..__len {
            let __orig = $bias[__i];
            $bias[__i] = __orig + __eps;
            let __lp: f32 = $loss;
            $bias[__i] = __orig - __eps;
            let __lm: f32 = $loss;
            $bias[__i] = __orig - __lr * ((__lp - __lm) / (2.0 * __eps));
        }
    }};
}
pub(crate) use update_bias_fd;
