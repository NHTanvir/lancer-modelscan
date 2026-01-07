//! Detector registry. The `define_detectors!` macro registers each default
//! detector at compile time; `default_detectors()` returns the boxed set.

use crate::detectors::{
    KerasLambdaLayer, ObfuscatedModule, OnnxCustomDomain, RiskyCall, SuspiciousReduce, TfCustomOp,
    UnknownImport,
};
use crate::Detector;

/// Register a fixed set of detector structs into a `Vec<Box<dyn Detector>>`.
#[macro_export]
macro_rules! define_detectors {
    ($($detector:expr),+ $(,)?) => {{
        let v: Vec<Box<dyn $crate::Detector>> = vec![ $( Box::new($detector) ),+ ];
        v
    }};
}

/// An ordered collection of detectors.
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        DetectorRegistry { detectors }
    }

    /// The default registry (all 7 built-ins).
    pub fn defaults() -> Self {
        DetectorRegistry::new(default_detectors())
    }

    /// Detectors, minus any whose id is in `excluded`.
    pub fn iter_enabled<'a>(
        &'a self,
        excluded: &'a std::collections::HashSet<String>,
    ) -> impl Iterator<Item = &'a (dyn Detector)> + 'a {
        self.detectors
            .iter()
            .map(|b| b.as_ref())
            .filter(move |d| !excluded.contains(d.id()))
    }

    pub fn ids(&self) -> Vec<&str> {
        self.detectors.iter().map(|d| d.id()).collect()
    }

    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }
}

/// The 7 default detectors, in evaluation order.
pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    define_detectors![
        RiskyCall,
        SuspiciousReduce,
        UnknownImport,
        ObfuscatedModule,
        TfCustomOp,
        OnnxCustomDomain,
        KerasLambdaLayer,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_seven() {
        assert_eq!(DetectorRegistry::defaults().len(), 7);
    }
}
