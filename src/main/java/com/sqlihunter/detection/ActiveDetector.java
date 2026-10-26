package com.sqlihunter.detection;

import com.sqlihunter.findings.Finding;
import com.sqlihunter.mutation.Param;

import java.util.List;

/** An active detection technique applied to a single parameter. */
public interface ActiveDetector {
    String name();

    /** Returns findings for this parameter (usually 0 or 1). Never throws. */
    List<Finding> test(Param param, ActiveContext ac);
}
