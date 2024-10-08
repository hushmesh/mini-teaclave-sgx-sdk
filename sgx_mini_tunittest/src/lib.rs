// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![no_std]

use log::info;

extern crate alloc;

#[macro_export]
macro_rules! rsgx_unit_tests {
    (
        $($f : expr),* $(,)?
    ) => {
        {
            rsgx_unit_test_start();
            $(rsgx_unit_test($f,stringify!($f));)*
            rsgx_unit_test_end()
        }
    }
}

pub fn rsgx_unit_test_start() {
    info!("start running tests");
}

pub fn rsgx_unit_test<F, R>(f: F, name: &str)
where
    F: FnOnce() -> R,
{
    info!("running test: {}", name);
    f();
}

pub fn rsgx_unit_test_end() -> usize {
    info!("tests passed");
    0
}
