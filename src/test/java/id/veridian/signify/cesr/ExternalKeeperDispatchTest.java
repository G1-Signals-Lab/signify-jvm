package id.veridian.signify.cesr;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import id.veridian.signify.cesr.Keeping.*;
import id.veridian.signify.cesr.params.KeeperParams;
import id.veridian.signify.core.Manager.Algos;
import id.veridian.signify.generated.keria.model.ExternState;
import id.veridian.signify.generated.keria.model.HabState;
import id.veridian.signify.generated.keria.model.KeyStateRecord;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class ExternalKeeperDispatchTest {
    @Test void dispatchesOnlyRegisteredModuleAndRestoresSamePublicDescriptor() {
        var calls = new AtomicInteger();
        var keeper = mock(Keeper.class);
        when(keeper.getAlgo()).thenReturn(Algos.extern);
        ExternalModuleType module = (pidx, descriptor) -> {
            assertEquals(7, pidx);
            assertEquals("windows-tpm-p256", descriptor.getParamsMap().get("extern_type"));
            assertEquals("public-reference", descriptor.getParamsMap().get("key_ref"));
            if (calls.get() == 1) assertEquals(List.of("public-key"), descriptor.getParamsMap().get("state_keys"));
            calls.incrementAndGet();
            return keeper;
        };
        var manager = new KeyManager(null, List.of(new ExternalModule("windows-tpm-p256", "hardware", module)));
        assertSame(keeper, manager.create(Algos.extern, 7, Map.of(
                "extern_type", "windows-tpm-p256", "extern", Map.of("key_ref", "public-reference"))));
        var external = new ExternState().externType("windows-tpm-p256").pidx(7)
                .putAdditionalProperty("key_ref", "public-reference");
        assertSame(keeper, manager.get(new HabState().extern(external)
                .state(new KeyStateRecord().k(List.of("public-key")))));
        assertEquals(2, calls.get());
        verify(keeper, never()).incept(anyBoolean());
        verify(keeper, never()).getSigners();
        verify(keeper, never()).sign(any());
    }

    @Test void missingUnknownMalformedAndDuplicateModulesFailClosed() {
        var manager = new KeyManager(null, List.of());
        assertThrows(IllegalArgumentException.class,
                () -> manager.create(Algos.extern, 0, Map.of("extern_type", "missing", "extern", Map.of())));
        assertThrows(UnsupportedOperationException.class, () -> manager.get(new HabState()));
        assertThrows(IllegalArgumentException.class,
                () -> manager.get(new HabState().extern(new ExternState().externType("missing").pidx(0))));
        ExternalModuleType module = (pidx, args) -> { fail("Unknown descriptor must never reach a provider"); return null; };
        var registration = new ExternalModule("hardware", "fixed", module);
        assertThrows(IllegalArgumentException.class,
                () -> new KeyManager(null, List.of(registration, registration)));
    }
}
